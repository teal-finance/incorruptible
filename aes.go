// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

package incorruptible

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"log"
)

type Cipher struct {
	gcm   cipher.AEAD
	nonce []byte
}

// NewAESCipher creates a cipher with Encrypt() and Decrypt() functions
// for AEAD (Authenticated Encryption with Associated Data).
//
// Implementation is based on:
// - https://wikiless.org/wiki/Authenticated_encryption
// - https://go.dev/blog/tls-cipher-suites
// - https://github.com/gtank/cryptopasta
//
// The underlying algorithm is AES-128 GCM:
// - AES is a symmetric encryption, faster than asymmetric (e.g. RSA)
// - 128-bit key is sufficient for most usages (256-bits is much slower)
//
// Assumption design: This library should be used on AES-supported hardware
// like AMD/Intel processors providing optimized AES instructions set.
// If this is not your case, please report a feature request
// to implement support for ChaCha20Poly1305.
//
// GCM (Galois Counter Mode) is preferred over CBC (Cipher Block Chaining)
// because of CBC-specific attacks and configuration difficulties.
// But, CBC is faster and does not have any weakness in our server-side use case.
// If requested, this implementation may change to use CBC.
// Your feedback or suggestions are welcome, please contact us.
//
// This package follows the Golang Cryptography Principles:
// https://golang.org/design/cryptography-principles
// Secure implementation, faultlessly configurable,
// performant and state-of-the-art updated.
func NewAESCipher(secretKey []byte) (Cipher, error) {
	var c Cipher

	if len(secretKey) != 16 {
		// prefer 16 bytes (AES-128, faster) over 32 (AES-256, irrelevant extra security).
		log.Panic("Want 128-bit AES key containing 16 bytes, but got ", len(secretKey))
	}

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return c, err
	}

	c.gcm, err = cipher.NewGCM(block)
	if err != nil {
		return c, err
	}

	// Never use more than 2^32 random nonces with a given key
	// because of the risk of a repeat (birthday attack).
	c.nonce = make([]byte, c.gcm.NonceSize())
	_, err = rand.Read(c.nonce)

	return c, err
}

// Encrypt encrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Output takes the
// form nonce|cipherText|tag where '|' indicates concatenation.
func (c *Cipher) Encrypt(plainText []byte) []byte {
	return c.gcm.Seal(nil, c.nonce, plainText, nil)
}

// Decrypt decrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Expects input
// form nonce|cipherText|tag where '|' indicates concatenation.
func (c *Cipher) Decrypt(cipherText []byte) ([]byte, error) {
	return c.gcm.Open(nil, c.nonce, cipherText, nil)
}
