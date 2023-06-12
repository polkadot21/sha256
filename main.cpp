// Disclaimer!
// This implementation should be used for educational purposes only.
// For the real-world scenario, use OpenSSL or Crypto++ which are optimized and well-tested implementations.

// Mimics the implementation described in:
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
// Also, mimics the Python implementation by A. Karpathy
// https://github.com/karpathy/cryptos/blob/main/cryptos/sha256.py


//Algorithm SHA-256:
//Input: message (an array of bytes)
//Output: hash (a 32-byte array)
//
//1. Initialize hash values:
//h0 = 0x6a09e667
//h1 = 0xbb67ae85
//h2 = 0x3c6ef372
//h3 = 0xa54ff53a
//h4 = 0x510e527f
//h5 = 0x9b05688c
//h6 = 0x1f83d9ab
//h7 = 0x5be0cd19
//
//2. Pre-process the message:
//a. Pad the message so its length (in bits) is congruent to 448 (mod 512)
//b. Append the bit length of the original message (before padding) as a 64-bit big-endian integer
//
//3. Process the message in successive 512-bit chunks:
//For each chunk
//        a. Divide the chunk into 16 32-bit big-endian words w[0..15]
//b. Extend the words into 64 32-bit words w[0..63] according to the SHA-256 schedule
//        c. Initialize hash values for this chunk: a=h0, b=h1, c=h2, d=h3, e=h4, f=h5, g=h6, h=h7
//d. Main loop:
//For i from 0 to 63
//T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + w[i]
//T2 = Sigma0(a) + Maj(a, b, c)
//h = g
//g = f
//f = e
//e = d + T1
//d = c
//c = b
//b = a
//a = T1 + T2
//e. Add the compressed chunk to the current hash value:
//h0 = h0 + a
//h1 = h1 + b
//h2 = h2 + c
//h3 = h3 + d
//h4 = h4 + e
//h5 = h5 + f
//h6 = h6 + g
//h7 = h7 + h
//
//4. The final hash value (message digest) is h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
//
//End Algorithm


#include <array>
#include <iostream>
#include <iomanip>
#include <cstring>  // for std::memset and std::memcpy

// First 32 bits of the fractional parts of the cube roots of the first 64 prime numbers
constexpr std::array<uint32_t, 64> K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Functions used in the SHA-256 algorithm.
// The names and operations are defined in the SHA-256 specification.
inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint32_t SHR(uint32_t x, uint32_t n) { return x >> n; }
inline uint32_t ROTR(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t Sigma0(uint32_t x) { return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22); }
inline uint32_t Sigma1(uint32_t x) { return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25); }
inline uint32_t sigma0(uint32_t x) { return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3); }
inline uint32_t sigma1(uint32_t x) { return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10); }

// SHA-256 hash computation involves manipulating a 512-bit block of data and a 256-bit state.
// The state is updated using the data block in a way that is hard to reverse, giving the hash function its security.
void sha256_transform(std::array<uint32_t, 8>& state, const std::array<uint32_t, 16>& block)
{
    std::array<uint32_t, 64> W;
    std::copy(block.begin(), block.end(), W.begin());

    // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
    for (size_t t = 16; t < 64; ++t)
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];

    auto a = state[0];
    auto b = state[1];
    auto c = state[2];
    auto d = state[3];
    auto e = state[4];
    auto f = state[5];
    auto g = state[6];
    auto h = state[7];

    // Main loop, which updates the hash state based on the input data:
    for (size_t t = 0; t < 64; ++t)
    {
        auto T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
        auto T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // Add the compressed chunk to the current hash value:
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

#include <string>  // for std::string and std::getline

int main() {
    // Get the input string
    std::string input;
    std::cout << "Enter a string to hash (up to 64 characters): ";
    std::getline(std::cin, input);

    if (input.size() > 64) {
        std::cout << "Input is too long. Please enter a string of 64 characters or less.\n";
        return 1;  // exit with an error code
    }

    // Convert the string to bytes
    std::array<uint8_t, 64> bytes;
    std::memset(bytes.data(), 0, bytes.size());  // set all bytes to 0
    std::memcpy(bytes.data(), input.data(), input.size());  // copy input to bytes

    // Add padding
    if (input.size() < 64) {
        bytes[input.size()] = 0x80;  // append a '1' bit followed by '0' bits
        // In a full SHA-256 implementation, we would also append the length of the input in bits to the end of the block.
        // However, this would require more than 64 bytes of input, so we skip this step in this simplified implementation.
    }

    // Convert the bytes to words
    std::array<uint32_t, 16> block;
    for (size_t i = 0; i < 16; ++i) {
        for (size_t j = 0; j < 4; ++j) {
            block[i] |= bytes[4*i+j] << (24 - 8*j);  // concatenate bytes to words
        }
    }

    // Initialize the hash state
    std::array<uint32_t, 8> state = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // Compute the hash
    sha256_transform(state, block);

    // Print the resulting hash
    for (const auto& word : state) {
        std::cout << std::hex << std::setw(8) << std::setfill('0') << word;
    }
    std::cout << '\n';

    return 0;
}


