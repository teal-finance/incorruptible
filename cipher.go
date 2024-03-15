// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

package incorruptible

import (
	"crypto/aes"
	"crypto/cipher"
	"math/rand"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	aesNonceSize = 12 // AES-128 nonce is 12 bytes
	gcmTagSize   = 16 // AES-GCM tag is 16 bytes
)

func NewCipher(secretKey []byte) cipher.AEAD {
	switch len(secretKey) {
	case 16:
		return NewAESCipher(secretKey)
	case 32:
		return NewChaCipher(secretKey)
	default:
		log.Panic("Unexpected secretKey length: ", len(secretKey), " bytes."+
			"Accept 16 bytes (128-bit AES key) "+
			" or 32 bytes (256-bit ChaCha20-Poly1305 key).")
		return nil
	}
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
// Assumption design: This function should be used on AES-supported hardware
// like AMD/Intel processors providing optimized AES instructions set.
// If this is not your case, please use NewChaChaCipher().
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
func NewAESCipher(secretKey []byte) cipher.AEAD {
	if len(secretKey) != 16 {
		// prefer 16 bytes (AES-128, faster) over 32 (AES-256, irrelevant extra security).
		log.Panic("Want 128-bit AES key containing 16 bytes, but got", len(secretKey))
	}

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		log.Panic("New AES cipher: ", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Panic("New AES-GCM cipher: ", err)
	}

	if gcm.NonceSize() != aesNonceSize {
		log.Panicf("New AES-GCM cipher: want nonceSize=%d but got=%d", aesNonceSize, gcm.NonceSize())
	}

	return gcm
}

// NewChaCipher creates a cipher for ChaCha20-Poly1305.
// with Encrypt() and Decrypt() functions.
func NewChaCipher(secretKey []byte) cipher.AEAD {
	if len(secretKey) != 32 {
		log.Panic("Want 256-bit key containing 32 bytes, but got", len(secretKey))
	}

	aead, err := chacha20poly1305.New(secretKey)
	if err != nil {
		log.Panic("New ChaCha20-Poly1305 Cipher: ", err)
	}

	return aead
}

// Encrypt encrypts data using the given cipher.
// Output takes the form "nonce|ciphertext|tag" where '|' indicates concatenation.
//
// "math/rand" is 40 times faster than "crypto/rand"
// see: https://github.com/SimonWaldherr/golang-benchmarks#random
//
//nolint:gosec // strong random generator not required for nonce
func Encrypt(aead cipher.AEAD, plaintext []byte) []byte {
	// the variable "all" will contain the nonce + the ciphertext + the potential GCM tag
	all := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+gcmTagSize)
	rand.Read(all) // write the nonce part only
	return aead.Seal(all, all, plaintext, nil)
}

// Decrypt decrypts the ciphertext using any AEAD cipher.
// The parameter "all" contains the nonce + the ciphertext + the potential GCM tag.
// in the format "nonce|ciphertext|tag" where '|' indicates concatenation.
func Decrypt(aead cipher.AEAD, all []byte) (plaintext []byte, err error) {
	nSize := aead.NonceSize()
	nonce, ciphertext := all[:nSize], all[nSize:]
	dst := ciphertext[:0]
	return aead.Open(dst, nonce, ciphertext, nil)
}
