mod trie;
mod miner;
mod device;

use device::Device;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::time::{Instant, Duration};
use sha2::{Sha256, Digest};
use std::sync::{Arc, mpsc};
use std::thread;
use clap::{App, Arg, SubCommand, crate_version, crate_authors, crate_description};
use trie::TrieNode;
use miner::Miner;
use rand::{rngs::OsRng, RngCore};
use anyhow::anyhow;

const TERMS_PATH: &str = "terms.txt";
const SOLUTIONS_PATH: &str = "solutions.txt";
const PRINT_HASH_RATE_INTERVAL: f64 = 1_f64;

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
    let res_byte = match byte / 7 {
        byte @ 0..=9 => byte + b'0',
        byte @ 10..=35 => byte + b'a' - 10,
        36 => b'e',
        _ => unreachable!(),
    };
    res_byte as char
}

/// Makes a Krist v2 address from a private key.
fn make_v2_address(pkey: &[u8]) -> String {
    let mut protein = [None; 9];
    let mut stick = digest(&digest(pkey));
    let mut v2 = String::from("k");

    for byte in protein.iter_mut() {
        *byte = Some(stick[0]);
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
        eprintln!("Warning: {}", format!($($arg)*))
    }
}

fn mine(selection: Vec<usize>) -> anyhow::Result<()> {
    let devices = Device::select(selection)?;

    let (trie, warnings) = TrieNode::from_file(TERMS_PATH)?;
    for warning in warnings.iter() {
        warn!("{}", warning);
    }
    let trie_encoded = trie.encode();
    println!("Term tree size: {} Bytes", trie_encoded.len() * 4);

    // Present devices
    for device in devices.iter() {
        println!("Using device: {}", device.name()?);
    }

    // Make miners
    println!("Starting miners...");
    let trie = Arc::new(trie_encoded);
    let (tx, rx) = mpsc::channel();
    let mut hash_rates = vec![0.0; devices.len()];
    for (i, device) in devices.into_iter().enumerate() {
        let tx = tx.clone();
        let trie = trie.clone();
        thread::spawn(move || {
            let mut entropy = [0_u8; 16];
            OsRng.fill_bytes(&mut entropy);

            match Miner::new(&entropy, &trie, i, device, tx.clone()) {
                Ok(mut miner) => {
                    if let Err(e) = miner.mine() {
                        warn!("Miner {} has errored: {}", i, e);
                    }
                }
                Err(e) => warn!("Could not build miner {}: {}", i, e),
            }
        });
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
        for (id, pkey, hash_rate) in results {
            hash_rates[id] = hash_rate;
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
        let total_hash_rate = hash_rates.iter().fold(0.0, |a, b| a + b);
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
                    arg.parse::<usize>()
                        .map(|_| ())
                        .map_err(|_| "must be a nonnegative integer".into())
                })));
    let matches = app.clone().get_matches();

    match matches.subcommand() {
        ("list", _) => {
            for (i, device) in Device::list_all()?.iter().enumerate() {
                let name = device.name().map_err(|e| anyhow!(e))?;
                println!("{}: {}", i, name);
            }
        },
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
