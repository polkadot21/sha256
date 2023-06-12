
# SHA-256 Simplified Implementation in C++
## Introduction
This repository contains a simplified implementation of the SHA-256 cryptographic hash function in C++. The SHA-256 algorithm generates a 256-bit (32-byte) hash value, typically rendered as a 64 digit hexadecimal number.

The implementation is meant for educational purposes and thus, it is not suitable for production use due to various limitations. Please refer to `sha256_pseudocode.md` for a detailed pseudocode description of the SHA-256 algorithm.

## Simplified SHA-256 Implementation
The provided C++ code offers a simple implementation of the SHA-256 transformation function. It takes as input a 512-bit block (a 16-element array of 32-bit words) and updates the current hash value (an 8-element array of 32-bit words).

Furthermore, the main function reads a string of up to 64 characters, converts it to a 512-bit block, and uses the SHA-256 transformation function to compute the hash. The resulting hash value is then printed to the standard output.

## Limitations
The following features of the full SHA-256 algorithm are not implemented:

- Full Padding: The code does append a '1' bit and as many '0' bits as required to pad the input to 64 bytes (512 bits), but it does not append the 64-bit integer representing the length of the original message in bits, which is a requirement of the SHA-256 algorithm.

- Message Blocking: SHA-256 is designed to handle messages of any length. Messages are split into 512-bit blocks, and each block is processed in turn. The provided code only processes a single block and does not handle message blocking.

- Byte Order: The SHA-256 algorithm is defined in terms of big-endian operations, but the provided code does not handle byte swapping to ensure the correct byte order on little-endian machines.

## TODOs
- Implement full padding, including appending the length of the original message in bits to the final block.
- Implement message blocking to handle messages of arbitrary length.
- Implement byte order swapping to ensure correct operation on both big-endian and little-endian machines.

## Disclaimer
This code is provided for educational purposes only. Implementing cryptographic algorithms yourself is generally discouraged because it's very easy to introduce subtle bugs that could compromise security. For real world applications, you should use a well-tested cryptographic library like OpenSSL or Crypto++.