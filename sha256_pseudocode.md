# Algorithm SHA-256:
### Input: message (an array of bytes)
### Output: hash (a 32-byte array)

##Initialize hash values:
   ```
   h0 = 0x6a09e667
   h1 = 0xbb67ae85
   h2 = 0x3c6ef372
   h3 = 0xa54ff53a
   h4 = 0x510e527f
   h5 = 0x9b05688c
   h6 = 0x1f83d9ab
   h7 = 0x5be0cd19
   ```
## Pre-process the message:
   a. Pad the message so its length (in bits) is congruent to 448 (mod 512)
   b. Append the bit length of the original message (before padding) as a 64-bit big-endian integer

## Process the message in successive 512-bit chunks:
   For each chunk
   - Divide the chunk into 16 32-bit big-endian words `w[0..15]`
   - Extend the words into 64 32-bit words `w[0..63]` according to the SHA-256 schedule
   - Initialize hash values for this chunk: `a=h0, b=h1, c=h2, d=h3, e=h4, f=h5, g=h6, h=h7`
   - Main loop:
   ```
   For i from 0 to 63
   T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + w[i]
   T2 = Sigma0(a) + Maj(a, b, c)
   h = g
   g = f
   f = e
   e = d + T1
   d = c
   c = b
   b = a
   a = T1 + T2
   ```
   - Add the compressed chunk to the current hash value:
   ```
   h0 = h0 + a
   h1 = h1 + b
   h2 = h2 + c
   h3 = h3 + d
   h4 = h4 + e
   h5 = h5 + f
   h6 = h6 + g
   h7 = h7 + h
   ```
## The final hash value (message digest) is:
`h0` append `h1` append `h2` append `h3` append `h4` append `h5` append `h6` append `h7`

## End Algorithm
