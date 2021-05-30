use std::{sync::mpsc::Sender, time::Instant};
use ocl::{Buffer, Device, Kernel, MemFlags, Platform, ProQue, SpatialDims, core::{DeviceInfo, DeviceInfoResult}};

const THREAD_ITER: usize = 4096;
const DESIRED_ITER_TIME: f64 = 1_f64;
const KERNEL_SRC: &str = include_str!("kernel.cl");

#[derive(Clone, Copy)]
pub struct PlatformDevice {
    pub platform: Platform,
    pub device: Device,
}

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
        entropy: &[u8],
        trie: &Vec<u32>,
        id: usize,
        platform_device: PlatformDevice,
        tx: Sender<(usize, Option<Vec<u8>>, f64)>
    ) -> ocl::Result<Self> {
        let platform = platform_device.platform;
        let device = platform_device.device;

        // Get local work size from device
        let local_size = device.info(DeviceInfo::MaxWorkGroupSize)?;
        let local_size = match local_size {
            DeviceInfoResult::MaxWorkGroupSize(local_size) => local_size,
            _ => 0_usize
        };

        // Build ProQue
        let pq_ocl = ProQue::builder()
            .platform(platform)
            .device(device)
            .src(KERNEL_SRC)
            .build()?;

        // Build buffers
        let entropy_buffer = Buffer::builder()
            .queue(pq_ocl.queue().clone())
            .flags(MemFlags::new().read_only())
            .len(10)
            .copy_host_slice(entropy)
            .build()?;

        let trie_buffer = Buffer::builder()
            .queue(pq_ocl.queue().clone())
            .flags(MemFlags::new().read_only())
            .len(trie.len())
            .copy_host_slice(&trie)
            .build()?;

        let solved_buffer: Buffer<u8> = Buffer::builder()
            .queue(pq_ocl.queue().clone())
            .flags(MemFlags::new().write_only())
            .len(1)
            .copy_host_slice(&[0])
            .build()?;

        let pkey_buffer: Buffer<u8> = Buffer::builder()
            .queue(pq_ocl.queue().clone())
            .flags(MemFlags::new().write_only())
            .len(32)
            .build()?;

        // Build kernel
        let kernel = pq_ocl.kernel_builder("mine")
            .global_work_size(local_size)
            .arg_named("entropy", &entropy_buffer)
            .arg_named("trie", &trie_buffer)
            .arg_named("nonce", 0u64)
            .arg_named("solved", &solved_buffer)
            .arg_named("pkey", &pkey_buffer)
            .build()?;

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

    pub fn mine(&mut self) {
        let mut vec_solved = vec![0];

        loop {
            let t0 = Instant::now();

            // Enqueue kernel and wait for it
            unsafe { self.kernel.enq() }.expect("Enqueue kernel");
            self.pq_ocl.finish().expect("Finish queue");

            // Read from solved
            self.solved_buffer.read(&mut vec_solved).enq()
                .expect("Read solved buffer");

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
                .expect("Set nonce argument");

            // Send information to the main thread
            if vec_solved[0] == 1 {
                let mut vec_pkey = vec![0; 32];
                self.solved_buffer.write(&vec_pkey[..1]).enq()
                    .expect("Clear solved buffer");
                self.pkey_buffer.read(&mut vec_pkey).enq()
                    .expect("Read pkey buffer");

                let dt = Instant::now() - t0;
                let hash_rate = THREAD_ITER as f64
                    * old_work_size as f64
                    / dt.as_secs_f64();

                self.tx.send((self.id, Some(vec_pkey), hash_rate))
                    .expect("Send message to main thread");
            } else {
                let dt = Instant::now() - t0;
                let hash_rate = THREAD_ITER as f64
                    * old_work_size as f64
                    / dt.as_secs_f64();

                self.tx.send((self.id, None, hash_rate))
                    .expect("Send message to main thread");
            }
        }
    }
}
