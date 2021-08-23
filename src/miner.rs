use crate::device::Device;
use std::{sync::mpsc::Sender, time::Instant};
use ocl::{Buffer, Kernel, MemFlags, ProQue, SpatialDims, core::{DeviceInfo, DeviceInfoResult}};
use anyhow::anyhow;

const THREAD_ITER: usize = 4096;
const DESIRED_ITER_TIME: f64 = 1_f64;
const KERNEL_SRC: &str = include_str!("kernel.cl");

macro_rules! res {
    ($expr:expr) => {
        $expr.map_err(|e| anyhow::anyhow!(e))
    }
}

pub struct Miner {
    id: usize,
    pq_ocl: ProQue,
    kernel: Kernel,
    solved_buffer: Buffer<u8>,
    pkey_buffer: Buffer<u8>,
    local_size: f64,
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
        let local_size = res!(device.device.info(DeviceInfo::MaxWorkGroupSize))?;
        let local_size = match local_size {
            DeviceInfoResult::MaxWorkGroupSize(local_size) => local_size as f64,
            _ => 0.0,
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
            .copy_host_slice(trie)
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
            .global_work_size(local_size as usize)
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
        })
    }

    fn enqueue_kernel(&self) -> anyhow::Result<()> {
        res!(unsafe { self.kernel.enq() })?;
        res!(self.pq_ocl.finish())
    }

    fn get_solved(&self) -> anyhow::Result<bool> {
        let mut solved = vec![0];
        res!(self.solved_buffer.read(&mut solved).enq())?;
        Ok(solved[0] == 1)
    }

    fn set_solved(&self, solved: bool) -> anyhow::Result<()> {
        res!(self.solved_buffer.write(&vec![solved as u8]).enq())
    }

    fn get_pkey(&self) -> anyhow::Result<Vec<u8>> {
        let mut pkey = vec![0; 32];
        res!(self.pkey_buffer.read(&mut pkey).enq())?;
        Ok(pkey)
    }

    pub fn mine(&mut self) -> anyhow::Result<()> {
        let mut nonce = 0u64;
        let mut work_size = self.local_size;
        let local_size = self.local_size;

        loop {
            let t0 = Instant::now();

            self.enqueue_kernel()?;

            // Recalculate global work size to match fixed iter time
            let dt = (Instant::now() - t0).as_secs_f64();
            let hash_rate = THREAD_ITER as f64 * work_size / dt;
            let desired_multiplier = DESIRED_ITER_TIME / dt;
            work_size *= desired_multiplier;
            work_size = f64::round(work_size / local_size) * local_size;
            work_size = f64::max(work_size, self.local_size);
            self.kernel.set_default_global_work_size(SpatialDims::One(work_size as usize));

            // Increment nonce
            nonce += 1;
            res!(self.kernel.set_arg("nonce", nonce))?;

            // Send information to the main thread
            if self.get_solved()? {
                self.set_solved(false)?;
                self.tx.send((self.id, Some(self.get_pkey()?), hash_rate))?;
            } else {
                self.tx.send((self.id, None, hash_rate))?;
            }
        }
    }
}
