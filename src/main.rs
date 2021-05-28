use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::path::Path;
use ocl::{Buffer, MemFlags, Platform, Device, ProQue, Kernel, SpatialDims};
use std::time::{Instant, Duration};
use sha2::{Sha256, Digest};
use std::cmp;
use std::cmp::{min, max};
use ocl::enums::{DeviceInfo};
use ocl::core::{DeviceInfoResult};
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::thread;
use std::env::args;
use std::ffi::OsStr;

const THREAD_ITER: usize = 4096;
const ADDRESS_LOOKUP: [char; 256] = ['0', '0', '0', '0', '0', '0', '0', '1', '1', '1', '1', '1', '1', '1', '2', '2', '2', '2', '2', '2', '2', '3', '3', '3', '3', '3', '3', '3', '4', '4', '4', '4', '4', '4', '4', '5', '5', '5', '5', '5', '5', '5', '6', '6', '6', '6', '6', '6', '6', '7', '7', '7', '7', '7', '7', '7', '8', '8', '8', '8', '8', '8', '8', '9', '9', '9', '9', '9', '9', '9', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'e', 'e', 'e', 'e', 'e', 'e', 'e', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'g', 'g', 'g', 'g', 'g', 'g', 'g', 'h', 'h', 'h', 'h', 'h', 'h', 'h', 'i', 'i', 'i', 'i', 'i', 'i', 'i', 'j', 'j', 'j', 'j', 'j', 'j', 'j', 'k', 'k', 'k', 'k', 'k', 'k', 'k', 'l', 'l', 'l', 'l', 'l', 'l', 'l', 'm', 'm', 'm', 'm', 'm', 'm', 'm', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'o', 'o', 'o', 'o', 'o', 'o', 'o', 'p', 'p', 'p', 'p', 'p', 'p', 'p', 'q', 'q', 'q', 'q', 'q', 'q', 'q', 'r', 'r', 'r', 'r', 'r', 'r', 'r', 's', 's', 's', 's', 's', 's', 's', 't', 't', 't', 't', 't', 't', 't', 'u', 'u', 'u', 'u', 'u', 'u', 'u', 'v', 'v', 'v', 'v', 'v', 'v', 'v', 'w', 'w', 'w', 'w', 'w', 'w', 'w', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'y', 'y', 'y', 'y', 'y', 'y', 'y', 'z', 'z', 'z', 'z', 'z', 'z', 'z', 'e', 'e', 'e', 'e'];
const TRIE_REV_ADDRESS_LOOKUP: [u8; 128] = [0, 0, 0, 0, 0, 0, 0, 0, /*8*/0, 0, 0, 0, 0, 0, 0, 0, /*16*/0, 0, 0, 0, 0, 0, 0, 0, /*24*/0, 0, 0, 0, 0, 0, 0, 0, /*32*/0, 0, 0, 0, 0, 0, 0, 0, /*40*/0, 0, 0, 0, 0, 0, 0, 0, /*48 ASCII 0*/0, 1, 2, 3, 4, 5, 6, 7, /*56*/8, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /*a*/10, 11, 12, 13, 14, 15, 16, 17, 18, 19, /*k*/20, 21, 22, 23, 24, 25, 26, 27, 28, 29, /*u*/30, 31, 32, 33, 34, /*z*/35, 0, 0, 0, 0, 0];
const KERNEL_SRC: &str = include_str!("kernel.cl");
const TERMS_PATH: &str = "terms.txt";
const SOLUTIONS_PATH: &str = "solutions.txt";
const DESIRED_ITER_TIME: f64 = 1_f64;
const PRINT_HASH_RATE_INTERVAL: f64 = 1_f64;
const AVERAGE_HASHRATE_ITER_COUNT: usize = 10_usize; 

/// Hashes a byte slice into a byte array, Krist style.
///
/// In pseudocode it's the same as `SHA256(hex(data))`.
fn digest(data: &[u8]) -> [u8; 32] {
    let hex = data.iter().fold(String::new(), |hex, byte| {
        hex + &format!("{:02x}", byte)
    });
    *Sha256::digest(hex.as_bytes()).as_ref()
}

/// Makes a Krist v2 address from a private key.
fn make_v2_address(pkey: &[u8]) -> String {
    let mut protein = [None; 9];
    let mut stick = digest(&digest(pkey));
    let mut v2 = String::from("k");

    for i in 0..9 {
        protein[i] = Some(stick[0]);
        stick = digest(&digest(&stick));
    }

    let mut i = 0;
    while i < 9 {
        let link = stick[i] % 9;
        match protein[link as usize] {
            Some(val) => {
                v2.push(ADDRESS_LOOKUP[val as usize]);
                protein[link as usize] = None;
                i += 1;
            }
            None => {
                stick = digest(&stick);
            }
        }
    }

    v2
}

/// Adds a branch node to a trie at a certain index. Updates the index to the index of the added
/// branch. Does nothing if a leaf node exists in the same place and follows a branch (without
/// adding other) if one exists in the same place.
fn add_branch(trie: &mut Vec<u32>, index: &mut usize, position: u8) {
    let data = trie[*index + position as usize];
    if data == 0 { // Empty
        // Add a new branch
        let new_index = (trie.len() / 36) - (*index / 36);
        for _ in 0..36 {trie.push(0)}
        trie[*index + position as usize] = new_index as u32 + 1;
        *index += new_index * 36;
    } else if data == 1 { // Leaf
        // A shorter prefix already exists, nothing to be done
    } else { // Branch
        // Follow the branch that already exists
        *index += (data - 1) as usize * 36;
    }
}

/// Adds a leaf node to a trie at a certain index. Does nothing if either a branch node or a leaf
/// node already exists in the same place.
fn add_leaf(trie: &mut Vec<u32>, index: &usize, position: u8) {
    let data = trie[*index + position as usize];
    if data == 0 { // Empty
        // Add the leaf
        trie[*index + position as usize] = 1;
    } else if data == 1 { // Leaf
        // The exact leaf we want already exists, nothing to be done
    } else { // Branch
        // A longer prefix already exists here
        // Should never happen (since they are supposed to be sorted by length)
    }
}

/// Makes a 36-ary trie (a.k.a prefix tree) out of a list of terms. Redundant terms (either repeated
/// terms or one term which is the result from appending to a shorter term) are ignored.
fn add_terms(trie: &mut Vec<u32>, prefixes: &Vec<&str>) {
    // Sort terms by shortest first
    let mut prefixes = prefixes.clone();
    prefixes.sort_unstable_by(
        |a, b|
            if (*a).len() < (*b).len() {
                cmp::Ordering::Less
            } else if (*a).len() == (*b).len() {
                cmp::Ordering::Equal
            } else {
                cmp::Ordering::Greater
            }
    );

    for prefix in prefixes {
        let prefix_bytes = prefix.as_bytes();
        let mut index: usize = 0;
        for i in 0..min(prefix.len(), 9) {
            let trie_byte = TRIE_REV_ADDRESS_LOOKUP[prefix_bytes[i] as usize];
            if i == prefix.len() - 1 {
                add_leaf(trie, &index, trie_byte);
            } else {
                add_branch(trie, &mut index, trie_byte);
            }
        }
    }
}

#[derive(Clone, Copy)]
struct PlatformDevice {
    platform: Platform,
    device: Device,
}

fn get_all_devices() -> Vec<PlatformDevice> {
    let mut result = Vec::new();
    let platforms = Platform::list();
    for platform in platforms {
        let platform_devices = Device::list_all(platform);
        match platform_devices {
            Ok(platform_devices) => {
                for device in platform_devices {
                    result.push(PlatformDevice {
                        device,
                        platform,
                    });
                }
            }
            Err(e) => {
                println!("ERROR: Could not load devices: {}", e);
                return Vec::new();
            }
        }
    }
    result
}

fn print_all_devices() {
    let platform_devices = get_all_devices();
    println!("Found {} devices", platform_devices.len());
    for i in 0..platform_devices.len() {
        let device = platform_devices[i].device;
        let mut buffer = String::new();
        buffer += &format!("Device {}:\n", i);
        let name = device.name();
        match name {
            Ok(name) => {
                buffer += &format!("\tName: {}\n", name);
            },
            Err(e) => {
                println!("ERROR: Could not load name for device #{}: {}", i, e);
                continue;
            }
        }
        let vendor = device.vendor();
        match vendor {
            Ok(vendor) => {
                buffer += &format!("\tVendor: {}\n", vendor);
            },
            Err(e) => {
                println!("ERROR: Could not load vendor info for device #{}: {}", i, e);
                continue;
            }
        }

        print!("{}", buffer);
    }
}

struct Miner {
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
    fn new(
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

    fn mine(&mut self) {
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
            let new_work_size = max(new_work_size, self.local_size);
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

fn mine(program_name: &str, arguments: Vec<String>) {
    // Parse arguments
    let all_devices_and_platforms = get_all_devices();
    let mut platforms_and_devices = Vec::new();
    if arguments.len() == 0 || arguments[0] == "all" {
        for i in 0..all_devices_and_platforms.len() {
            platforms_and_devices.push(all_devices_and_platforms[i]);
        }
    } else {
        let mut user_selected = vec![false; all_devices_and_platforms.len()];
        for i in 0..arguments.len() {
            let arg = &arguments[i];
            let arg = match arg.parse::<usize>() {
                Ok(arg) => arg,
                Err(e) => {
                    println!("ERROR: Could not parse argument {} (\"{}\"): {}", i, arg, e);
                    continue;
                },
            };
            if arg >= all_devices_and_platforms.len() {
                println!("ERROR: Argument {} (\"{}\") indicates an unavailable device", i, arg);
                continue;
            }
            user_selected[arg] = true;
        }
        for i in 0..all_devices_and_platforms.len() {
            if user_selected[i] {
                platforms_and_devices.push(all_devices_and_platforms[i]);
            }
        }
    }

   // Read terms
    let path = Path::new(TERMS_PATH);
    let mut terms_file = match File::open(&path) {
        Err(e) => {
            println!("ERROR: Could not open {}: {}", TERMS_PATH, e);
            panic!("Open terms file");
        },
        Ok(val) => val,
    };
    let mut terms_string = String::new();
    if let Err(e) = terms_file.read_to_string(&mut terms_string) {
        println!("ERROR: Could not read {}: {}", TERMS_PATH, e);
        panic!("Read terms file");
    }
    if !terms_string.is_ascii() {
        println!("ERROR: Expected {} to only contain ASCII", TERMS_PATH);
        panic!("Parse terms file");
    }
    let mut terms = Vec::new();
    for word in terms_string.split_ascii_whitespace() {
        terms.push(word)
    }
    let mut trie = vec![0_u32; 36];
    add_terms(&mut trie, &terms);
    println!("Term tree size: {} Bytes", trie.len() * 4);
    println!("Loaded {} terms", terms.len());

    // Present devices
    println!("Using {} devices:", platforms_and_devices.len());
    if platforms_and_devices.len() == 0 {
        println!("NOTE: Run {} list to list all devices", program_name);
        println!(
            "NOTE: Run {} mine [id device_0 [device_1 [...]]] to mine with some devices",
            program_name
        );
    }
    for platform_and_device in platforms_and_devices.iter() {
        let device = platform_and_device.device;
        let name = match device.name() {
            Ok(name) => name,
            Err(_) => continue,
        };
        println!("\tUsing device: {}", name);
    }

    // Make miners
    println!("Starting miners...");
    let (tx, rx) = mpsc::channel();
    let mut miners = Vec::new();
    for i in 0..platforms_and_devices.len() {
        let mut entropy = [0_u8; 10];
        getrandom::getrandom(&mut entropy).expect("Get system entropy");
        let miner = Miner::new(
            &entropy,
            &trie,
            i,
            platforms_and_devices[i],
            tx.clone(),
        );
        let miner = match miner {
            Ok(miner) => miner,
            Err(e) => {
                eprintln!("ERROR: Could not build miner #{}: {}", i, e);
                continue;
            }
        };
        miners.push(miner);
    }
    let mut hash_rates = Vec::new();
    for mut miner in miners {
        thread::spawn(move || miner.mine());
        hash_rates.push(vec![0_f64]);
    }

    let solutions_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(SOLUTIONS_PATH);
    let mut solutions_file = match solutions_file {
        Ok(solutions_file) => solutions_file,
        Err(e) => {
            println!("ERROR: Could not open {}: {}", SOLUTIONS_PATH, e);
            panic!("Open solutions file");
        }
    };

    // Get and present information from miners
    let mut num_solutions = 0;
    let t_start = Instant::now();
    loop {
        // Fetch results from miner threads
        let mut solutions = Vec::new();
        let results = rx.try_iter();
        for result in results {
            let (id, pkey, hash_rate) = result;

            hash_rates[id].push(hash_rate);
            if hash_rates[id].len() > AVERAGE_HASHRATE_ITER_COUNT {
                hash_rates[id].remove(0);
            }

            if let Some(pkey) = pkey {
                solutions.push(pkey);
            }
        }

        // Present solutions
        for solution in solutions.iter() {
            print!("New solution: ");
            for byte in solution {
                print!("{:02x}", byte);
            }
            println!(": {}", make_v2_address(&solution));
        }

        // Format solutions
        num_solutions += solutions.len();
        let mut info_buffer = String::new();
        info_buffer += &format!("{:>3} Solutions Found | ", num_solutions);

        // Compute and format hash rate
        // Average each miner's rate if there's more than 1, use rate from last loop if there's none
        let mut total_hash_rate = 0_f64;
        for i in 0..hash_rates.len() {
            if hash_rates[i].len() != 0 {
                let mut miner_hr = 0_f64;
                for hr in hash_rates[i].iter() {
                    miner_hr += *hr;
                }
                total_hash_rate += miner_hr / hash_rates[i].len() as f64;
            }
        }
        if total_hash_rate > 1E9 {
            info_buffer += &format!("{:>6.3} GA/s", total_hash_rate / 1E9);
        } else if total_hash_rate > 1E6 {
            info_buffer += &format!("{:>6.2} MA/s", total_hash_rate / 1E6);
        } else if total_hash_rate > 1E3 {
            info_buffer += &format!("{:>6.1} kA/s", total_hash_rate / 1E3);
        } else {
            info_buffer += &format!("{:>6.0}  A/s", total_hash_rate);
        }

        // Format time
        let dt = Instant::now() - t_start;
        let mut deaccumullator = dt.as_secs();
        let t_secs = deaccumullator % 60;
        deaccumullator /= 60;
        let t_mins = deaccumullator % 60;
        deaccumullator /= 60;
        let t_hours = deaccumullator % 24;
        let t_days = deaccumullator / 24;
        info_buffer += &format!(
            " | {:>2}d {:>2}h {:>2}min {:>2}sec",
            t_days,
            t_hours,
            t_mins,
            t_secs,
        );

        // Present info
        println!("{}", info_buffer);

        // Save solutions
        for solution in solutions.iter() {
            let mut buffer = String::new();
            for byte in solution {
                buffer += &format!("{:02x}", byte);
            }
            buffer += " ";
            buffer += &make_v2_address(solution);
            buffer += "\n";
            if let Err(e) = solutions_file.write(buffer.as_bytes()) {
                println!("ERROR: Could not write to {}: {}", SOLUTIONS_PATH, e);
            }
        }
        if let Err(e) = solutions_file.flush() {
            println!("ERROR: Could not flush file {}: {}", SOLUTIONS_PATH, e);
        }

        // Sleep
        thread::sleep(Duration::from_secs_f64(PRINT_HASH_RATE_INTERVAL));
    }
}

fn print_usage(program_name: &str) {
    println!("pmkam - PG's Messy (OpenCL) Krist Address Miner v{}", env!("CARGO_PKG_VERSION"));
    println!("This is a prefix-only miner with multiple term support. Put the terms you want to \
              look for in a \"{}\" file. Results are written to the \"{}\" file \
              as well as presented on the screen.", TERMS_PATH, SOLUTIONS_PATH);
    println!("Some parts of this program are licensed under different terms and are attributed \
              to their respective authors. This includes all dependencies from crates.io and part \
              of the kernel.cl file.");
    println!("Usage:\n\t\
              {0} mine [device_0 [device_1 [...]]] - Starts the miner with some devices\n\t\
              {0} mine all - Starts the miner with all devices\n\t\
              {0} list - Displays all devices\n\t\
              {0} help - Displays this", program_name);
}

pub fn main() {
    let program_name = args()
        .next()
        .as_ref()
        .map(Path::new)
        .and_then(Path::file_name)
        .and_then(OsStr::to_str)
        .map(String::from)
        .unwrap();

    // * i need a proper argument parser what am i doing * //
    let arg_0 = args()
        .skip(1)
        .next();
    let arg_0 = arg_0
        .as_ref()
        .and_then(|a| Some(a.as_str()));

    match arg_0 {
        Some("help") => print_usage(&program_name),
        Some("mine") => mine(&program_name, args().skip(2).collect()),
        Some("list") => print_all_devices(),
        Some(_) => print_usage(&program_name),
        None => print_usage(&program_name),
    }
}
