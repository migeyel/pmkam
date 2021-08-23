use crate::device::Device;
use std::{sync::mpsc::Sender, time::Instant};
use ocl::{Buffer, Kernel, MemFlags, ProQue, SpatialDims, core::{DeviceInfo, DeviceInfoResult}};
use anyhow::anyhow;

const THREAD_ITER: usize = 4096;
const DESIRED_ITER_TIME: f64 = 1_f64;
const KERNEL_SRC: &str = include_str!("kernel.cl");

pub struct Miner {
    id: usize,
    pq_ocl: ProQue,
    kernel: Kernel,
    solved_buffer: Buffer<u8>,
    pkey_buffer: Buffer<u8>,
    nonce: u64,
    local_size: usize,
    work_size: usize,
    tx: Sender<(usize, Option<Vec<u8>>, f64)>
}

impl Miner {
    pub fn new(
        entropy: &[u8; 16],
        trie: &[u32],
        id: usize,
        device: Device,
        tx: Sender<(usize, Option<Vec<u8>>, f64)>
    ) -> anyhow::Result<Self> {
        // Get local work size from device
        let local_size = device.device.info(DeviceInfo::MaxWorkGroupSize)
            .map_err(|e| anyhow!(e))?;
        let local_size = match local_size {
            DeviceInfoResult::MaxWorkGroupSize(local_size) => local_size,
            _ => 0_usize
        };

        // Build ProQue
        let pq_ocl = ProQue::builder()
            .platform(device.platform)
            .device(device.device)
            .src(KERNEL_SRC)
            .build()
            .map_err(|e| anyhow!(e))?;

        // Build buffers
        let entropy_buffer = Buffer::builder()
            .queue(pq_ocl.queue().clone())
            .flags(MemFlags::new().read_only())
            .len(16)
            .copy_host_slice(&entropy[..])
            .build()
            .map_err(|e| anyhow!(e))?;

        let trie_buffer = Buffer::builder()
            .queue(pq_ocl.queue().clone())
            .flags(MemFlags::new().read_only())
            .len(trie.len())
            .copy_host_slice(&trie)
            .build()
            .map_err(|e| anyhow!(e))?;

        let solved_buffer: Buffer<u8> = Buffer::builder()
            .queue(pq_ocl.queue().clone())
            .flags(MemFlags::new().write_only())
            .len(1)
            .copy_host_slice(&[0])
            .build()
            .map_err(|e| anyhow!(e))?;

        let pkey_buffer: Buffer<u8> = Buffer::builder()
            .queue(pq_ocl.queue().clone())
            .flags(MemFlags::new().write_only())
            .len(32)
            .build()
            .map_err(|e| anyhow!(e))?;

        // Build kernel
        let kernel = pq_ocl.kernel_builder("mine")
            .global_work_size(local_size)
            .arg_named("entropy", &entropy_buffer)
            .arg_named("trie", &trie_buffer)
            .arg_named("nonce", 0u64)
            .arg_named("solved", &solved_buffer)
            .arg_named("pkey", &pkey_buffer)
            .build()
            .map_err(|e| anyhow!(e))?;

        Ok(Self {
            id,
            pq_ocl,
            kernel,
            solved_buffer,
            pkey_buffer,
            local_size,
            tx,
            nonce: 0_u64,
            work_size: local_size,
        })
    }

    pub fn mine(&mut self) -> anyhow::Result<()> {
        let mut vec_solved = vec![0];

        loop {
            let t0 = Instant::now();

            // Enqueue kernel and wait for it
            unsafe { self.kernel.enq() }.map_err(|e| anyhow!(e))?;
            self.pq_ocl.finish().map_err(|e| anyhow!(e))?;

            // Read from solved
            self.solved_buffer.read(&mut vec_solved).enq()
                .map_err(|e| anyhow!(e))?;

            // Re-calculate global work size to match the fixed iter time
            let dt = Instant::now() - t0;
            let dt_vs_desired_coefficient = DESIRED_ITER_TIME / dt.as_secs_f64();
            let new_work_size = f64::round(
                (self.work_size as f64 * dt_vs_desired_coefficient) / self.local_size as f64
            ) as usize * self.local_size;
            let new_work_size = std::cmp::max(new_work_size, self.local_size);
            let old_work_size = self.work_size;
            if new_work_size != old_work_size {
                self.kernel.set_default_global_work_size(SpatialDims::One(new_work_size));
                self.work_size = new_work_size;
            }

            // Increment nonce
            self.nonce += 1;
            self.kernel.set_arg("nonce", self.nonce)
                .map_err(|e| anyhow!(e))?;

            // Send information to the main thread
            if vec_solved[0] == 1 {
                let mut vec_pkey = vec![0; 32];
                self.solved_buffer.write(&vec_pkey[..1]).enq()
                    .map_err(|e| anyhow!(e))?;
                self.pkey_buffer.read(&mut vec_pkey).enq()
                    .map_err(|e| anyhow!(e))?;

                let dt = Instant::now() - t0;
                let hash_rate = THREAD_ITER as f64
                    * old_work_size as f64
                    / dt.as_secs_f64();

                self.tx.send((self.id, Some(vec_pkey), hash_rate))
                    .map_err(|e| anyhow!(e))?;
            } else {
                let dt = Instant::now() - t0;
                let hash_rate = THREAD_ITER as f64
                    * old_work_size as f64
                    / dt.as_secs_f64();

                self.tx.send((self.id, None, hash_rate))
                    .map_err(|e| anyhow!(e))?;
            }
        }
    }
}
