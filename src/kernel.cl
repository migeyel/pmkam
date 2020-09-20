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

// sha256 initial hash values
#define H0 0x6a09e667
#define H1 0xbb67ae85
#define H2 0x3c6ef372
#define H3 0xa54ff53a
#define H4 0x510e527f
#define H5 0x9b05688c
#define H6 0x1f83d9ab
#define H7 0x5be0cd19

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
void sha256_transform(const UINT data[16], UINT H[8]) {
    int i;
    uint a, b, c, d, e, f, g, h, t1, t2, m[64];

#pragma unroll
    for (i = 0; i < 16; i++) m[i] = data[i].i;

#pragma unroll
    for (i = 16; i < 64; i++) m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = H[0].i;
    b = H[1].i;
    c = H[2].i;
    d = H[3].i;
    e = H[4].i;
    f = H[5].i;
    g = H[6].i;
    h = H[7].i;

#pragma unroll
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
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
void sha256_transform2(UINT H[8]) {
    int i;
    uint a, b, c, d, e, f, g, h, t1, t2;

    a = H[0].i;
    b = H[1].i;
    c = H[2].i;
    d = H[3].i;
    e = H[4].i;
    f = H[5].i;
    g = H[6].i;
    h = H[7].i;

#pragma unroll
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K2[i];
        t2 = EP0(a) + MAJ(a, b, c);
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
// uchar data[64] - input bytes - will be modified
// uchar hash[32] - output bytes - will be modified
void digest64(const UINT data[16], UINT hash[8]) {
    // init hash state
    hash[0].i = H0;
    hash[1].i = H1;
    hash[2].i = H2;
    hash[3].i = H3;
    hash[4].i = H4;
    hash[5].i = H5;
    hash[6].i = H6;
    hash[7].i = H7;

    // transform twice
    sha256_transform(data, hash);
    sha256_transform2(hash);
}

// Address miner

#define THREAD_ITER 4096 // How many addresses each work unit checks
#define CHAIN_SIZE (16 * 8) // 16 stored iterations with 8 bytes each
#define MAX_CHAIN_ITER 16 // The max amout of iterations the check_address function does before giving up.
                          // Must not be greater than CHAIN_SIZE / 8. (otherwise false positives will happen without any other benefit).
                          // A max chain iter of n means a failure probability of at most (7/9)^n per address checked.

// Converts a sha256 hash to hexadecimal
inline void hash_to_hex(const UINT hash[8], UINT hex[16]) {    
#pragma unroll
    for (int i = 0; i < 16; i += 2) {
        uchar h, h1, h2;

        h = UINT_BYTE_BE(hash[i / 2], 0);
        h1 = h % 16;
        h2 = h / 16;
        UINT_BYTE_BE(hex[i], 1) = h1 < 10 ? h1 + '0' : h1 + 'a' - 10;
        UINT_BYTE_BE(hex[i], 0) = h2 < 10 ? h2 + '0' : h2 + 'a' - 10;

        h = UINT_BYTE_BE(hash[i / 2], 1);
        h1 = h % 16;
        h2 = h / 16;
        UINT_BYTE_BE(hex[i], 3) = h1 < 10 ? h1 + '0' : h1 + 'a' - 10;
        UINT_BYTE_BE(hex[i], 2) = h2 < 10 ? h2 + '0' : h2 + 'a' - 10;

        h = UINT_BYTE_BE(hash[i / 2], 2);
        h1 = h % 16;
        h2 = h / 16;
        UINT_BYTE_BE(hex[i + 1], 1) = h1 < 10 ? h1 + '0' : h1 + 'a' - 10;
        UINT_BYTE_BE(hex[i + 1], 0) = h2 < 10 ? h2 + '0' : h2 + 'a' - 10;

        h = UINT_BYTE_BE(hash[i / 2], 3);
        h1 = h % 16;
        h2 = h / 16;
        UINT_BYTE_BE(hex[i + 1], 3) = h1 < 10 ? h1 + '0' : h1 + 'a' - 10;
        UINT_BYTE_BE(hex[i + 1], 2) = h2 < 10 ? h2 + '0' : h2 + 'a' - 10;
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
inline uchar make_address_byte_s(uchar byte) {
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
    uchar chain[CHAIN_SIZE];
    uchar protein[18];
    uint protein_start;
} HASH_CHAIN_T;

// Advances a hash chain by 1 iteration:
// - Sets last_hash to sha256(last_hash).
// - Writes the address byte from the first byte from the chain buffer to the
//   protein buffer.
// - Writes the first 8 bytes from last_hash to the chain buffer.
inline void shift_chain(HASH_CHAIN_T *chain) {
    UINT hash_hex[16];
    hash_to_hex(chain->last_hash, hash_hex);
    digest64(hash_hex, chain->last_hash);

    chain->protein[chain->protein_start] = make_address_byte_s(
        chain->chain[chain->chain_start]
    );
    chain->protein_start = (chain->protein_start + 1) % 18;

    chain->chain[chain->chain_start + 0] = UINT_BYTE_BE(chain->last_hash[0], 0);
    chain->chain[chain->chain_start + 1] = UINT_BYTE_BE(chain->last_hash[0], 1);
    chain->chain[chain->chain_start + 2] = UINT_BYTE_BE(chain->last_hash[0], 2);
    chain->chain[chain->chain_start + 3] = UINT_BYTE_BE(chain->last_hash[0], 3);
    chain->chain[chain->chain_start + 4] = UINT_BYTE_BE(chain->last_hash[1], 0);
    chain->chain[chain->chain_start + 5] = UINT_BYTE_BE(chain->last_hash[1], 1);
    chain->chain[chain->chain_start + 6] = UINT_BYTE_BE(chain->last_hash[1], 2);
    chain->chain[chain->chain_start + 7] = UINT_BYTE_BE(chain->last_hash[1], 3);
    chain->chain_start = (chain->chain_start + 8) % CHAIN_SIZE;
}

// 0 - Dead end
// 1 - There are valid prefixes
// 2 - There is a full term that matches this
inline int iter_prefix_search(const uchar addr_char, uint* index, __global const uint *trie) {
    uint trie_data;

    trie_data = trie[*index + addr_char];
    if (trie_data == 0) {
        return 0;
    } else if (trie_data == 1) {
        return 2;
    } else {
        *index += (trie_data - 1) * 36;
        return 1;
    }
}

// Given a hash chain, uses its information to generate an address without hashing anything
// such that the resulting address' pkey can be found from the seed that constructed the hash chain
inline bool check_address(const HASH_CHAIN_T *chain,__global const uint *trie) {
    uint chain_index = chain->chain_start;
    uint link;
    uint iter = 0;
    uchar v2[9];

    int i = 0;
    uint trie_index = 0;
    bool used_protein[9] = {};
    while (i < 8 && iter < MAX_CHAIN_ITER) {
        link = chain->chain[chain_index + i] % 9;
        if (!used_protein[link]) {
            v2[i] = chain->protein[(chain->protein_start + 2 * link) % 18];
            used_protein[link] = true;

            int found = iter_prefix_search(v2[i], &trie_index, trie);
            if (found == 0) {
                return false;
            } else if (found == 2) {
                return true;
            }

            i++;
        } else {
            chain_index = (chain_index + 8) % CHAIN_SIZE;
            iter++;
        }
    }

    if (iter >= MAX_CHAIN_ITER) {
        return 0;
    }

    // Put in last char in the address
    for (i = 0; i < 9; i++) {
        if (!used_protein[i]) {
            v2[8] = chain->protein[(chain->protein_start + 2 * i) % 18];
            break;
        }
    }

    return iter_prefix_search(v2[8], &trie_index, trie) == 2;
}

__kernel void mine(
    __constant const uchar *entropy,      // 10 bytes
    __global const uint *trie,            // Variable size
    const ulong nonce,
    __global uchar *solved,               // 1 byte
    __global uchar *pkey                  // 32 bytes
) {
    uint gid = get_global_id(0);

    // Generate seed from hashing some arguments
    uint gid_seed = gid;
    ulong nonce_seed = nonce;
    UINT seed[16] = {};
    
    UINT_BYTE_BE(seed[0], 0) = entropy[0];
    UINT_BYTE_BE(seed[0], 1) = entropy[1];
    UINT_BYTE_BE(seed[0], 2) = entropy[2];
    UINT_BYTE_BE(seed[0], 3) = entropy[3];
    UINT_BYTE_BE(seed[1], 0) = entropy[4];
    UINT_BYTE_BE(seed[1], 1) = entropy[5];
    UINT_BYTE_BE(seed[1], 2) = entropy[6];
    UINT_BYTE_BE(seed[1], 3) = entropy[7];
    UINT_BYTE_BE(seed[2], 0) = entropy[8];
    UINT_BYTE_BE(seed[2], 1) = entropy[9];
    seed[3].i = gid_seed;
    seed[4].i = nonce_seed % UINT_MAX;
    seed[5].i = nonce_seed / UINT_MAX;

    UINT seed_hash[8];
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
    for (int i = 0; i < CHAIN_SIZE; i += 8) {
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

    // Re-do hashes to find proper pkey
    // This *may* be faster to do on CPU due to higher clock frequencies
    if (solution_found) {
        UINT hash_byte[8];
        UINT hash_hex[16];
        hash_to_hex(seed_hash, hash_hex);

        for (int i = 0; i < solution_found_at; i++) {
            digest64(hash_hex, hash_byte);
            hash_to_hex(hash_byte, hash_hex);
        }

        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 4; j++) {
                printf("%c", UINT_BYTE_BE(hash_hex[i], j));
            }
        }
        printf("\n");

        *solved = 1;
        for (int i = 0; i < 32; i += 4) {
            pkey[i + 0] = UINT_BYTE_BE(hash_byte[i / 4], 0);
            pkey[i + 1] = UINT_BYTE_BE(hash_byte[i / 4], 1);
            pkey[i + 2] = UINT_BYTE_BE(hash_byte[i / 4], 2);
            pkey[i + 3] = UINT_BYTE_BE(hash_byte[i / 4], 3);
        }
    }
}
