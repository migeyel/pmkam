# pmkam - PG's Messy (OpenCL) Krist Address Miner
A miner for finding [Krist](https://krist.ceriat.net) addresses with a desired prefix (or group of prefixes).

## Usage
Similar to [KristVanity](https://github.com/Lignum/KristVanity). Put the prefixes you want to look for in a file named `terms.txt`
in the same folder as the program. The results will be written on the screen and to a file named `results.txt`.

Running `pmkam mine` will start mining on all devices it can find. You can run `pmkam help` for info
on how to enable specific devices and how to list them.

## Download
Pre-built binaries for x64 Windows and Linux can be found in the releases page. If you want to build it, you'll need to set up Rust
and also have the proper OpenCL headers and libraries.
