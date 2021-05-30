mod trie;
mod miner;

use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use ocl::{Platform, Device};
use std::time::{Instant, Duration};
use sha2::{Sha256, Digest};
use std::sync::mpsc;
use std::thread;
use clap::{App, Arg, SubCommand, crate_version, crate_authors, crate_description};
use trie::TrieNode;
use miner::Miner;
use anyhow::anyhow;

const TERMS_PATH: &str = "terms.txt";
const SOLUTIONS_PATH: &str = "solutions.txt";
const PRINT_HASH_RATE_INTERVAL: f64 = 1_f64;
const AVERAGE_HASHRATE_ITER_COUNT: usize = 10_usize;

fn hex(bytes: &[u8]) -> String {
    bytes.iter()
        .fold(String::new(), |s, byte| s + &format!("{:02x}", byte))
}

/// Hashes a byte slice into a byte array, Krist style.
///
/// In pseudocode it's the same as `SHA256(hex(data))`.
fn digest(data: &[u8]) -> [u8; 32] {
    *Sha256::digest(hex(data).as_bytes()).as_ref()
}

fn make_address_byte(byte: u8) -> char {
    match byte / 7 {
        byte @ 0..=9 => (byte + '0' as u8) as char,
        byte @ 10..=35 => (byte + 'a' as u8 - 10) as char,
        36 => 'e',
        _ => unreachable!(),
    }
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
        if let Some(val) = protein[link as usize] {
            v2.push(make_address_byte(val));
            protein[link as usize] = None;
            i += 1;
        } else {
            stick = digest(&stick);
        }
    }

    v2
}

macro_rules! warn {
    ($($arg:tt)*) => {
        eprintln!("Warning: {}", format!($($arg)*));
    }
}

fn get_all_devices() -> Vec<Device> {
    let mut result = Vec::new();
    for platform in Platform::list().iter() {
        match Device::list_all(platform) {
            Ok(platform_devices) => {
                for device in platform_devices.into_iter() {
                    result.push(device);
                }
            }
            Err(e) => {
                warn!("Could not load devices: {}", e);
                continue;
            }
        }
    }
    result
}

fn print_all_devices() {
    let devices = get_all_devices();
    println!("Found {} devices", devices.len());
    for i in 0..devices.len() {
        let mut buffer = String::new();
        buffer += &format!("Device {}:\n", i);
        
        let device = devices[i];
        match device.name() {
            Ok(name) => {
                buffer += &format!("\tName: {}\n", name);
            },
            Err(e) => {
                warn!("Could not load name for device {}: {}", i, e);
                continue;
            }
        }
        match device.vendor() {
            Ok(vendor) => {
                buffer += &format!("\tVendor: {}\n", vendor);
            },
            Err(e) => {
                warn!("Could not load vendor for device #{}: {}", i, e);
                continue;
            }
        }

        print!("{}", buffer);
    }
}

fn mine(mut arguments: Vec<usize>) -> anyhow::Result<()> {
    let all_devices = get_all_devices();
    let devices = if arguments.is_empty() {
        all_devices
    } else {
        arguments.sort_unstable();
        all_devices.into_iter()
            .zip(0..)
            .filter(|di| arguments.binary_search(&di.1).is_ok())
            .map(|di| di.0)
            .collect()
    };

    let mut terms = File::open(TERMS_PATH)
        .map_err(|e| anyhow!("Could not open {}: {}", TERMS_PATH, e))?;
    let mut terms_string = String::new();
    terms.read_to_string(&mut terms_string)
        .map_err(|e| anyhow!("Could not read {}: {}", TERMS_PATH, e))?;
    let lines = terms_string.lines()
        .map(|l| l.trim())
        .collect::<Vec<_>>();
    let (trie, warnings) = TrieNode::from_terms(&lines);
    for warning in warnings.iter() {
        warn!("{}", warning);
    }
    let trie_encoded = trie.encode();
    println!("Term tree size: {} Bytes", trie_encoded.len() * 4);

    // Present devices
    println!("Using {} devices:", devices.len());
    for device in devices.iter() {
        if let Ok(name) = device.name() {
            println!("\tUsing device: {}", name);
        }
    }

    // Make miners
    println!("Starting miners...");
    let (tx, rx) = mpsc::channel();
    let mut miners = Vec::new();
    for i in 0..devices.len() {
        let mut entropy = [0_u8; 10];
        getrandom::getrandom(&mut entropy)?;
        let miner = Miner::new(
            &entropy,
            &trie_encoded,
            i,
            devices[i],
            tx.clone(),
        );
        let miner = match miner {
            Ok(miner) => miner,
            Err(e) => {
                warn!("Could not build miner #{}: {}", i, e);
                continue;
            }
        };
        miners.push(miner);
    }
    let mut hash_rates = Vec::new();
    for (mut miner, i) in miners.into_iter().zip(0..) {
        thread::spawn(move || {
            if let Err(e) = miner.mine() {
                warn!("Miner {} has errored: {}", i, e);
            }
        });
        hash_rates.push(vec![0_f64]);
    }

    let mut solutions_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(SOLUTIONS_PATH)
        .map_err(|e| anyhow!("Could not open {}: {}", SOLUTIONS_PATH, e))?;

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
        for sol in solutions.iter() {
            println!("New solution: {}: {}", hex(sol), make_v2_address(sol));
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
        for sol in solutions.iter() {
            let line = format!("{} {}\n", hex(sol), make_v2_address(sol));
            if let Err(e) = solutions_file.write(line.as_bytes()) {
                warn!("Could not write to {}: {}", SOLUTIONS_PATH, e);
            }
        }
        if let Err(e) = solutions_file.flush() {
            warn!("Could not flush file {}: {}", SOLUTIONS_PATH, e);
        }

        // Sleep
        thread::sleep(Duration::from_secs_f64(PRINT_HASH_RATE_INTERVAL));
    }
}

pub fn main() -> anyhow::Result<()> {
    let after_help = format!(
        "pmkam is a prefix-only vanity miner with multiple term support. \
        Put the prefixes you want to search for in a \"{}\" file. \
        Results are written to a \"{}\" file as well as presented on the \
        screen.",
        TERMS_PATH, SOLUTIONS_PATH,
    );

    let mut app = App::new("pmkam")
        .max_term_width(80)
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .after_help(&*after_help)
        .subcommand(SubCommand::with_name("list")
            .about("Displays all available devices"))
        .subcommand(SubCommand::with_name("mine")
            .about("Mines for prefixes")
            .arg(Arg::with_name("devices")
                .help("Specify devices to mine with")
                .long("devices")
                .takes_value(true)
                .multiple(true)
                .use_delimiter(true)
                .validator(|arg| {
                    if let Err(_) = arg.parse::<usize>() {
                        Err("must be a nonnegative integer".into())
                    } else {
                        Ok(())
                    }
                })));
    let matches = app.clone().get_matches();

    match matches.subcommand() {
        ("list", _) => print_all_devices(),
        ("mine", Some(matches)) => {
            let values = matches.values_of("devices")
                .unwrap_or_default()
                .map(|v| v.parse().unwrap())
                .collect::<Vec<usize>>();
            mine(values)?;
        }
        _ => {
            app.print_help()?;
            println!();
        }
    }

    Ok(())
}
