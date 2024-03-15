# Security Design

The Incorruptible package provides a Cipher
with simple and safe functions `Encrypt()` and `Decrypt()` for
AEAD (Authenticated Encryption with Associated Data).  
See <https://wikiless.org/wiki/Authenticated_encryption>.

## Inspiration

This package has been inspired from:

- <https://go.dev/blog/tls-cipher-suites>
- <https://github.com/gtank/cryptopasta>

## Supported ciphers

Cipher            | Secret key length
------------------|--------------------
AES-128 GCM       | 128 bits (16 bytes)
ChaCha20-Poly1305 | 256 bits (32 bytes)

Incorruptible selects the cipher depending on the length of the provided secret key.

The AES cipher should be used on AES-supported hardware only
like AMD/Intel processors providing optimized AES instructions set.

If this is not your case, please provide a 32-bytes key
to select the ChaCha20-Poly1305 cipher.

## AES-128 GCM

Advantages:

- AES is a symmetric encryption, faster than asymmetric (e.g. RSA)
- 128-bit key is sufficient for most usages (256-bits is much slower)

## Galois Counter Mode

GCM (Galois Counter Mode) is preferred over CBC (Cipher Block Chaining)
because of CBC-specific attacks and configuration difficulties.
But, CBC is faster and does not have any weakness in our server-side use case.
If requested, this implementation may change to use CBC.
Your feedback or suggestions are welcome, please contact us.

## Principles

The Incorruptible aims to follow the Golang Cryptography Principles:  
<https://golang.org/design/cryptography-principles>

1. Secure implementation
2. Faultlessly configurable
3. Performant
4. State-of-the-art updated
