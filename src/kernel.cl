// Sha256 and Address Miner Kernel
// Sha256 code from kristforge (legacy branch)
// https://github.com/tmpim/kristforge/tree/legacy
// Licensed under MIT

// types
#define UCHARV uchar
#define UINTV uint
#define LONGV long

// functions
#define CONVERT(t, x) (t)(x)
#define VLOAD(x, y) (y)[(x)]
#define VSTORE(x, y, z) (z)[(y)] = (x)

// right rotate macro
#define RR(x, y) rotate((UINTV)(x), -((UINTV)(y)))

// sha256 macros
#define CH(x, y, z) bitselect((z),(y),(x))
#define MAJ(x, y, z) bitselect((x),(y),(z)^(x))
#define EP0(x) (RR((x),2) ^ RR((x),13) ^ RR((x),22))
#define EP1(x) (RR((x),6) ^ RR((x),11) ^ RR((x),25))
#define SIG0(x) (RR((x),7) ^ RR((x),18) ^ ((x) >> 3))
#define SIG1(x) (RR((x),17) ^ RR((x),19) ^ ((x) >> 10))

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

// perform a single round of sha256 transformation on the given data
void sha256_transform(UCHARV *data, UINTV *H) {
    int i;
    UINTV a, b, c, d, e, f, g, h, t1, t2, m[64];

#pragma unroll
    for (i = 0; i < 16; i++) {
        m[i] = (CONVERT(UINTV, data[i * 4]) << 24) |
               (CONVERT(UINTV, data[i * 4 + 1]) << 16) |
               (CONVERT(UINTV, data[i * 4 + 2]) << 8) |
               (CONVERT(UINTV, data[i * 4 + 3]));
    }

#pragma unroll
    for (i = 16; i < 64; i++) m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

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

    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}

void sha256_finish(UINTV *H, UCHARV *hash) {
    int l;

#pragma unroll
    for (int i = 0; i < 4; i++) {
        l = 24 - i * 8;
        hash[i] = CONVERT(UCHARV, (H[0] >> l) & 0x000000ff);
        hash[i + 4] = CONVERT(UCHARV, (H[1] >> l) & 0x000000ff);
        hash[i + 8] = CONVERT(UCHARV, (H[2] >> l) & 0x000000ff);
        hash[i + 12] = CONVERT(UCHARV, (H[3] >> l) & 0x000000ff);
        hash[i + 16] = CONVERT(UCHARV, (H[4] >> l) & 0x000000ff);
        hash[i + 20] = CONVERT(UCHARV, (H[5] >> l) & 0x000000ff);
        hash[i + 24] = CONVERT(UCHARV, (H[6] >> l) & 0x000000ff);
        hash[i + 28] = CONVERT(UCHARV, (H[7] >> l) & 0x000000ff);
    }
}

// sha256 digest of up to 55 bytes of input
// uchar data[64] - input bytes - will be modified
// uint inputLen - input length (in bytes)
// uchar hash[32] - output bytes - will be modified
void digest55(UCHARV *data, uint len, UCHARV *hash) {
    // pad input
    data[len] = 0x80;
    data[62] = (len * 8) >> 8;
    data[63] = len * 8;

    // init hash state
    UINTV H[8] = {H0, H1, H2, H3, H4, H5, H6, H7};

    // transform
    sha256_transform(data, H);

    // finish
    sha256_finish(H, hash);
}

// sha256 digest of 56 to 119 bytes of input
// uchar data[128] - input bytes - will be modified
// uint inputLen - input length (in bytes)
// uchar hash[32] - output bytes - will be modified
void digest119(uchar *data, uint inputLen, uchar *hash) {
    // pad input
    data[inputLen] = 0x80;
    data[126] = (inputLen * 8) >> 8;
    data[127] = inputLen * 8;

    // init hash state
    uint H[8] = { H0, H1, H2, H3, H4, H5, H6, H7 };

    // transform twice
    sha256_transform(data, H);
    sha256_transform(data + 64, H);

    // finish
    sha256_finish(H, hash);
}

#define THREAD_ITER 4096 // How many addresses each work unit checks
#define CHAIN_SIZE (16 * 8) // 16 stored iterations with 8 bytes each
#define MAX_CHAIN_ITER 16 // The max amout of iterations the check_address function does before giving up.
                          // Must not be greater than CHAIN_SIZE / 8. (otherwise false positives will happen without any other benefit).
                          // A max chain iter of n means a failure probability of at most (7/9)^n per address checked.

__constant uchar hex_lookup[16] = "0123456789abcdef";

// Converts a sha256 hash to hexadecimal
// uchar hash[32] - input hash
// uchar hex[128] - output hex - will be modified
// We write to 128 bytes because that's what digest119 expects
inline void hash_to_hex(const uchar *hash, uchar *hex) {
#pragma unroll
    for (int i = 0; i < 32; i++) {
        uchar h = hash[i];

        hex[2 * i] = hex_lookup[h / 16];
        hex[2 * i + 1] = hex_lookup[h % 16];
    }

    // digest119 (from sha256 spec) expects a zero padding
#pragma unroll
    for (uint i = 64; i < 128; i++) {
        hex[i] = 0;
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
// -chain: the first 8 bytes from every hash that is outputted from iterating sha256
// -last_hash: the (32-byte) hash from the last iteration
// -start: (8 * (how many iterations have occured)) % (chain size)
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
    uchar last_hash[32];
    uint start;
    uchar chain[CHAIN_SIZE];
} HASH_CHAIN_T;

// makev2address' protein table
// Composed of:
// chars_even - 9 address chars (in trie_char form)
// chars_odd - 9 address chars (in trie_char form)
// chars - a pointer that points to either *chars_even or *chars_odd
// is_even - bool that tells if we're in an even or odd cicle
//
// The protein struct is used to reduce the size of the full chain.
// It stores the first byte of what the chain stored up to 18 iterations ago.
// This works because Kristwallet only needs the first byte from the first
// 18 iterations to make an address.
// Since the chain shifts every hash but the protein uses double hashing,
// we need to keep track of 2 parallel proteins that come from either the
// odd positions or the even positions in the chain. 
typedef struct PROTEIN_T {
    uchar chars_even[9];
    uchar chars_odd[9];
    uchar *chars;
    bool is_even;
    uchar start;
} PROTEIN_T;

// Advances a hash chain by 1 iteration:
// -sets last_hash to sha256(last_hash)
// -overwrites the next 8 bytes starting from start with the first 8 bytes from last_hash
// -increments start by 8 (modulo the chain size)
inline void shift_chain(HASH_CHAIN_T *chain) {
    uchar hash_hex[128] = "";

    //hash_to_hex(chain->last_hash, hash_hex);
#pragma unroll
    for (int i = 0; i < 32; i++) {
        uchar h = chain->last_hash[i];
        hash_hex[2 * i] = (h >> 4) + (h < 160 ? '0' : 'a' - 10);
        h &= 0xf;
        hash_hex[2 * i + 1] = h + (h < 10 ? '0' : 'a' - 10);
    }
    digest119(hash_hex, 64, chain->last_hash);
    for (int i = 0; i < 8; i++) {
        chain->chain[chain->start + i] = chain->last_hash[i];
    }
    chain->start = (chain->start + 8) % CHAIN_SIZE;
}

// Advances a protein and a chain by 1 iteration
inline void shift_protein_and_chain(PROTEIN_T *protein, HASH_CHAIN_T *chain) {
    if (protein->is_even) {
        protein->chars_even[protein->start] = make_address_byte_s(chain->chain[chain->start]);
        protein->is_even = false;
        protein->chars = protein->chars_odd;
    } else {
        protein->chars_odd[protein->start] = make_address_byte_s(chain->chain[chain->start]);
        protein->start = (protein->start + 1) % 9;
        protein->is_even = true;
        protein->chars = protein->chars_even;
    }
    shift_chain(chain);
}

// 0 - Dead end
// 1 - There are valid prefixes
// 2 - There is a full term that matches this
inline int iter_prefix_search(const uchar addr_char, uint* index, __constant const ushort *trie) {
    uchar sub_byte;
    ushort trie_data;

    sub_byte = addr_char % 6;
    trie_data = trie[*index + sub_byte];
    if (trie_data == 0) {
        return 0;
    } else if (trie_data == 1) {
        return 2;
    } else {
        *index += (trie_data - 1) * 6;
    }

    sub_byte = addr_char / 6;
    trie_data = trie[*index + sub_byte];
    if (trie_data == 0) {
        return 0;
    } else if (trie_data == 1) {
        return 2;
    } else {
        *index += (trie_data - 1) * 6;
    }

    return 1;
}

// Given a hash chain, uses its information to generate an address without hashing anything
// such that the resulting address' pkey can be found from the seed that constructed the hash chain
inline bool check_address(PROTEIN_T *protein, const HASH_CHAIN_T *chain,__constant const ushort *trie) {
    uint chain_index = chain->start;
    uint link;
    uint iter = 0;
    uchar v2[9];

    int i = 0;
    uint trie_index = 0;
    bool used_protein[9] = {};
    while (i < 8 && iter < MAX_CHAIN_ITER) {
        link = chain->chain[chain_index + i] % 9;
        if (!used_protein[link]) {
            v2[i] = protein->chars[(protein->start + link) % 9];
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
            v2[8] = protein->chars[(protein->start + i) % 9];
            break;
        }
    }

    return iter_prefix_search(v2[8], &trie_index, trie) == 2;
}

__kernel void mine(
    __constant const uchar *entropy,      // 10 bytes
    __constant const ushort *trie,        // Variable size
    const ulong nonce,
    __global uchar *solved,               // 1 byte
    __global uchar *pkey                  // 32 bytes
) {
    uint gid = get_global_id(0);

    // Generate seed from hashing some arguments
    uint gid_seed = gid;
    ulong nonce_seed = nonce;
    uchar seed[64] = "";
    uint seedlen = 0;
    for (int i = 0; i < 10; i++) {
        seed[seedlen] = entropy[i];
        seedlen++;
    }
    for (int i = 0; i < 4; i++) {
        seed[seedlen] = gid_seed % 256;
        gid_seed /= 256;
        seedlen++;
    }
    for (int i = 0; i < 8; i++) {
        seed[seedlen] = nonce_seed % 256;
        nonce_seed /= 256;
        seedlen++;
    }
    uchar seed_hash[32] = {};
    digest55(seed, seedlen, seed_hash);

    // Make chain and protein
    HASH_CHAIN_T chain;
    chain.start = 0;

    PROTEIN_T protein;
    protein.start = 0;
    protein.is_even = true;

    // Put seed into the last chain hash
    for (int i = 0; i < 32; i++) {
        chain.last_hash[i] = seed_hash[i];
    }

    // Populate chain
    shift_chain(&chain); // krist's makev2address hashes the pkey twice before doing its thing
    shift_chain(&chain); // if the address from 0 or 1 was a match, we would not have the key without doing this

    for (int i = 0; i < CHAIN_SIZE; i += 8) {
        shift_protein_and_chain(&protein, &chain);
    }
    for (int i = 1; i < 18; i++) {
        shift_protein_and_chain(&protein, &chain);
    }

    // Mine
    bool solution_found = false;
    uint solution_found_at;
    for (int i = 0; i < THREAD_ITER; i++) {
        if (check_address(&protein, &chain, trie)) {
            solution_found = true;
            solution_found_at = i;
        }
        shift_protein_and_chain(&protein, &chain);
    }

    // Re-do hashes to find proper pkey
    // This *may* be faster to do on CPU due to higher clock frequencies
    if (solution_found) {
        uchar hash_byte[32];
        uchar hash_hex[128];
        hash_to_hex(seed_hash, hash_hex);

        for (int i = 0; i < solution_found_at; i++) {
            digest119(hash_hex, 64, hash_byte);
            hash_to_hex(hash_byte, hash_hex);
        }

        for (int i = 0; i < 32; i++) {
            *solved = 1;
            pkey[i] = hash_byte[i];
        }
    }
}