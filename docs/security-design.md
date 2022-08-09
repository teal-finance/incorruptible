# Security Design

The Incorruptible package provides a Cipher
with simple and safe functions `Encrypt()` and `Decrypt()` for
AEAD (Authenticated Encryption with Associated Data).  
See <https://wikiless.org/wiki/Authenticated_encryption>.

## Inspiration

This package has been inspired from:

- <https://go.dev/blog/tls-cipher-suites>
- <https://github.com/gtank/cryptopasta>

## AES-128

The underlying algorithm is AES-128 GCM:

- AES is a symmetric encryption, faster than asymmetric (e.g. RSA)
- 128-bit key is sufficient for most usages (256-bits is much slower)

## Assumption design

This library should be used on AES-supported hardware
like AMD/Intel processors providing optimized AES instructions set.
If this is not your case, please report a feature request
to implement support for ChaCha20Poly1305.

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
