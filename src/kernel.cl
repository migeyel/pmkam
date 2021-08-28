// Sha256 and Address Miner Kernel
// Sha256 code from kristforge (legacy branch)
// https://github.com/tmpim/kristforge/tree/legacy
// Licensed under MIT
// Modifications licensed under the pmkam project license

// Sha256

typedef union UINT {
    uint i;
    uchar c[4];
} UINT;

#ifdef __ENDIAN_LITTLE__
    #define UINT_BYTE_BE(U, I) ((U).c[3 - (I)])
#else
    #define UINT_BYTE_BE(U, I) ((U).c[(I)])
#endif

// right rotate macro
#define RR(x, y) rotate((uint)(x), -((uint)(y)))

// sha256 macros
#define CH(x, y, z) bitselect((z), (y), (x))
#define MAJ(x, y, z) bitselect((x), (y), (z) ^ (x))
#define EP0(x) (RR((x), 2) ^ RR((x), 13) ^ RR((x), 22))
#define EP1(x) (RR((x), 6) ^ RR((x), 11) ^ RR((x), 25))
#define SIG0(x) (RR((x), 7) ^ RR((x), 18) ^ ((x) >> 3))
#define SIG1(x) (RR((x), 17) ^ RR((x), 19) ^ ((x) >> 10))

// sha256 round constants
__constant uint K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// sha256 round constants added to a precomputed schedule of
// the second block from a 64-byte message
__constant uint K2[64] = {
    0xc28a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf374,
    0x649b69c1, 0xf0fe4786, 0x0fe1edc6, 0x240cf254, 0x4fe9346f, 0x6cc984be, 0x61b9411e, 0x16f988fa,
    0xf2c65152, 0xa88e5a6d, 0xb019fc65, 0xb9d99ec7, 0x9a1231c3, 0xe70eeaa0, 0xfdb1232b, 0xc7353eb0,
    0x3069bad5, 0xcb976d5f, 0x5a0f118f, 0xdc1eeefd, 0x0a35b689, 0xde0b7a04, 0x58f4ca9d, 0xe15d5b16,
    0x007f3e86, 0x37088980, 0xa507ea32, 0x6fab9537, 0x17406110, 0x0d8cd6f1, 0xcdaa3b6d, 0xc0bbbe37,
    0x83613bda, 0xdb48a363, 0x0b02e931, 0x6fd15ca7, 0x521afaca, 0x31338431, 0x6ed41a95, 0x6d437890,
    0xc39c91f2, 0x9eccabbd, 0xb5c9a0e6, 0x532fb63c, 0xd2c741c6, 0x07237ea3, 0xa4954b68, 0x4c191d76
};

// perform a single round of sha256 transformation on the given data
inline void sha256_transform(UINT m[64], UINT H[8]) {
    #pragma unroll
    for (int i = 16; i < 64; i++) {
        m[i].i = SIG1(m[i - 2].i)
            + m[i - 7].i
            + SIG0(m[i - 15].i)
            + m[i - 16].i;
    }

    uint a = H[0].i;
    uint b = H[1].i;
    uint c = H[2].i;
    uint d = H[3].i;
    uint e = H[4].i;
    uint f = H[5].i;
    uint g = H[6].i;
    uint h = H[7].i;

    #pragma unroll
    for (int i = 0; i < 64; i++) {
        uint t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i].i;
        uint t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    H[0].i += a;
    H[1].i += b;
    H[2].i += c;
    H[3].i += d;
    H[4].i += e;
    H[5].i += f;
    H[6].i += g;
    H[7].i += h;
}

// perform a single round of sha256 transformation on the second block of a
// 64-byte message
inline void sha256_transform2(UINT H[8]) {
    uint a = H[0].i;
    uint b = H[1].i;
    uint c = H[2].i;
    uint d = H[3].i;
    uint e = H[4].i;
    uint f = H[5].i;
    uint g = H[6].i;
    uint h = H[7].i;

    #pragma unroll
    for (int i = 0; i < 64; i++) {
        uint t1 = h + EP1(e) + CH(e, f, g) + K2[i];
        uint t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    H[0].i += a;
    H[1].i += b;
    H[2].i += c;
    H[3].i += d;
    H[4].i += e;
    H[5].i += f;
    H[6].i += g;
    H[7].i += h;
}

// sha256 digest of exactly 64 bytes of input
// UINT data[64] - input bytes - will be modified
// UINT hash[8] - output bytes - will be modified
inline void digest64(UINT data[64], UINT hash[8]) {
    hash[0].i = 0x6a09e667;
    hash[1].i = 0xbb67ae85;
    hash[2].i = 0x3c6ef372;
    hash[3].i = 0xa54ff53a;
    hash[4].i = 0x510e527f;
    hash[5].i = 0x9b05688c;
    hash[6].i = 0x1f83d9ab;
    hash[7].i = 0x5be0cd19;

    sha256_transform(data, hash);
    sha256_transform2(hash);
}

// Address miner

#define THREAD_ITER 4096 // How many addresses each work unit checks
#define CHAIN_SIZE 32

// Converts a sha256 hash to hexadecimal
inline void hash_to_hex(const UINT hash[8], UINT hex[64]) {    
    #pragma unroll
    for (int i = 0; i < 16; i += 2) {
        uchar h, h1, h2;

        h = UINT_BYTE_BE(hash[i / 2], 0);
        h1 = h % 16;
        h2 = h / 16;
        UINT_BYTE_BE(hex[i], 1) = h1 + (h1 < 10 ? '0' : 'a' - 10);
        UINT_BYTE_BE(hex[i], 0) = h2 + (h2 < 10 ? '0' : 'a' - 10);

        h = UINT_BYTE_BE(hash[i / 2], 1);
        h1 = h % 16;
        h2 = h / 16;
        UINT_BYTE_BE(hex[i], 3) = h1 + (h1 < 10 ? '0' : 'a' - 10);
        UINT_BYTE_BE(hex[i], 2) = h2 + (h2 < 10 ? '0' : 'a' - 10);

        h = UINT_BYTE_BE(hash[i / 2], 2);
        h1 = h % 16;
        h2 = h / 16;
        UINT_BYTE_BE(hex[i + 1], 1) = h1 + (h1 < 10 ? '0' : 'a' - 10);
        UINT_BYTE_BE(hex[i + 1], 0) = h2 + (h2 < 10 ? '0' : 'a' - 10);

        h = UINT_BYTE_BE(hash[i / 2], 3);
        h1 = h % 16;
        h2 = h / 16;
        UINT_BYTE_BE(hex[i + 1], 3) = h1 + (h1 < 10 ? '0' : 'a' - 10);
        UINT_BYTE_BE(hex[i + 1], 2) = h2 + (h2 < 10 ? '0' : 'a' - 10);
    }
}

// Converts a byte to the one used by the trie
// byte | krist | trie_char
// 0    | 0     | 0
// 6    | 0     | 0
// 7    | 1     | 1
// 69   | 9     | 9
// 70   | a     | 10
// 251  | z     | 35
// 252  | e     | 14
// 255  | e     | 14
inline uchar addr_byte(uchar byte) {
    uchar byte_div_7 = byte / 7;
    if (byte_div_7 == 36) {
        return 14;
    }
    return byte_div_7;
}

// A 'hash chain'
// Composed of:
// - chain: A circular buffer with the first 8 bytes from every hash that is
//          outputted from iterating sha256.
// - last_hash: The (32-byte) hash from the last iteration.
// - chain_start: The write pointer for the chain buffer.
// - protein: A circular buffer with trie_char form of the first byte from each
//            chain hash, shifted back by 18 iterations.
// - protein_start: The write pointer for the protein buffer.
//
// Instead of doing 30+ hashes for every address we check, we iterate
// the hash several times and put the result in an array, referred to here
// as the 'hash chain'.
// Krist uses information from H(pk), H(H(pk)), H(H(H(pk))), ... to make
// an address. we store all these in an array and we 'shift' the array such
// that pk' = H(pk); H(pk') = H(H(pk)), ... Shifting the chain like this
// requires only a single call to sha256 and yields a new pkey/address pair
// to check for term matches.
// Finally, Kristwallet only needs the first 8 bytes from every hash, so
// we only store that (as well as the seed and last hash, so we can shift).
typedef struct HASH_CHAIN_T {
    UINT last_hash[8];
    uint chain_start;
    uchar chain[CHAIN_SIZE * 8];
    uchar protein[18];
    uint protein_start;
} HASH_CHAIN_T;

// Advances a hash chain by 1 iteration:
// - Sets last_hash to sha256(last_hash).
// - Writes the address byte from the first byte from the chain buffer to the
//   protein buffer.
// - Writes the first 8 bytes from last_hash to the chain buffer.
inline void shift_chain(HASH_CHAIN_T *chain) {
    UINT hash_hex[64];
    hash_to_hex(chain->last_hash, hash_hex);
    digest64(hash_hex, chain->last_hash);

    chain->protein[chain->protein_start] = addr_byte(chain->chain[chain->chain_start]);
    chain->protein_start = (chain->protein_start + 1) % 18;

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        chain->chain[chain->chain_start + i] = UINT_BYTE_BE(chain->last_hash[i / 4], i % 4);
    }
    chain->chain_start = (chain->chain_start + 8) % (CHAIN_SIZE * 8);
}

// Goes down the trie branch at *index on char addr_char.
// Sets *index to the child index and returns:
// 0: If there is no child (i.e. no terms match the trie path)
// 1: If the child is not a leaf (i.e. some term shares a prefix with the path)
// 2: If the child is a leaf (i.e. a term matches the path exactly)
inline int down_branch(const uchar addr_char, uint* index, __global const uint *trie) {
    uint trie_data;

    trie_data = trie[*index + addr_char];
    switch (trie_data) {
        case 0:
            return 0;
        case 1:
            return 2;
        default:
            *index += (trie_data - 1) * 36;
            return 1;
    }
}

// Returns whether the address generated by the hash chain matches some term in
// the given term trie.
inline bool check_address(const HASH_CHAIN_T *chain,__global const uint *trie) {
    uint chain_index = chain->chain_start;
    uint link;
    uint iter = 0;
    uchar v2[9];

    // Krist address loop.
    // Using chain->chain for permutation indexes and chain->protein for the
    // already computed protein.
    // Going down the term trie as the chars are generated, so it can exit early
    // on a dead end or full match.
    int i = 0;
    uint trie_index = 0;
    bool used_protein[9] = {};
    while (i < 8) {
        link = chain->chain[chain_index + i] % 9;
        if (!used_protein[link]) {
            v2[i] = chain->protein[(chain->protein_start + 2 * link) % 18];
            used_protein[link] = true;

            int found = down_branch(v2[i], &trie_index, trie);
            switch (found) {
                case 0:
                    return false;
                case 1:
                    i++;
                    break;
                case 2:
                    return true;
            }
        } else {
            chain_index = (chain_index + 8) % (CHAIN_SIZE * 8);
            iter++;
            if (iter >= CHAIN_SIZE) {
                return false;
            }
        }
    }

    // Put in last char in the address
    #pragma unroll
    for (int i = 0; i < 9; i++) {
        if (!used_protein[i]) {
            v2[8] = chain->protein[(chain->protein_start + 2 * i) % 18];
            break;
        }
    }

    return down_branch(v2[8], &trie_index, trie) == 2;
}

__kernel void mine(
    __constant const uchar *entropy,      // 16 bytes
    __global const uint *trie,            // Variable size
    const ulong nonce,
    __global uchar *solved,               // 1 byte
    __global uchar *pkey                  // 32 bytes
) {
    uint gid = get_global_id(0);

    // Generate seed from hashing id, nonce and entropy.
    UINT seed[64] = {};
    UINT seed_hash[8];
    for (int i = 0; i < 16; i++) {
        UINT_BYTE_BE(seed[i / 4], i % 4) = entropy[i];
    }
    seed[4].i = gid;
    seed[5].i = nonce % UINT_MAX;
    seed[6].i = nonce / UINT_MAX;
    digest64(seed, seed_hash);

    // Make chain and protein
    HASH_CHAIN_T chain;
    chain.chain_start = 0;
    chain.protein_start = 0;

    // Put seed into the last chain hash
    for (int i = 0; i < 8; i++) {
        chain.last_hash[i] = seed_hash[i];
    }

    // Populate chain
    shift_chain(&chain); // krist's makev2address hashes the pkey twice before doing its thing
    shift_chain(&chain); // if the address from 0 or 1 was a match, we would not have the key without doing this
    for (int i = 1; i < 18; i++) {
        shift_chain(&chain);
    }
    for (int i = 0; i < CHAIN_SIZE; i++) {
        shift_chain(&chain);
    }

    // Mine
    bool solution_found = false;
    uint solution_found_at;
    for (int i = 0; i < THREAD_ITER; i++) {
        if (check_address(&chain, trie)) {
            solution_found = true;
            solution_found_at = i;
        }
        shift_chain(&chain);
    }

    // Re-do hashes to reconstruct the pkey.
    if (solution_found) {
        UINT hash_byte[8];
        UINT hash_hex[64];
        hash_to_hex(seed_hash, hash_hex);

        for (int i = 0; i < solution_found_at; i++) {
            digest64(hash_hex, hash_byte);
            hash_to_hex(hash_byte, hash_hex);
        }

        *solved = 1;
        for (int i = 0; i < 32; i++) {
            pkey[i] = UINT_BYTE_BE(hash_byte[i / 4], i % 4);
        }
    }
}
