// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

// Package incorruptible provides a safer, shorter, faster
// secret token for session cookie and Authorization HTTP header.
package incorruptible

import (
	"errors"
	"fmt"
	"log"
	"time"
)

const (
	// Base91MinSize and ciphertextMinSize need to be adapted according
	// on any change about expiry encoding size, padding size….
	Base91MinSize    = 42
	encryptedMinSize = 12 + 6 + 16 // nonce + min cypherText + tag

	// noSpaceDoubleQuoteSemicolon exclude character not welcome in cookie token:
	// space, double-quote ", semi-colon ; and back-slash \
	// This Base91 encoding alphabet is shuffled at startup time
	// using the (secret) encryption key.
	noSpaceDoubleQuoteSemicolon = "" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789!#$%&()*+,-./:<=>?@[]^_`{|}~'"

	doPrint = false
)

func (incorr *Incorruptible) Encode(tv TValues) (string, error) {
	printV("Encode", tv, errors.New(""))

	plainText, err := Marshal(tv, incorr.magic)
	if err != nil {
		return "", err
	}
	printB("Encode plaintext", plainText)

	nonceAndCipherTextAndTag := Encrypt(incorr.cipher, plainText)
	printB("Encode ciphertext", nonceAndCipherTextAndTag)

	str := incorr.baseN.EncodeToString(nonceAndCipherTextAndTag)
	printS("Encode BaseXX", str)
	return str, nil
}

func (incorr *Incorruptible) Decode(str string) (TValues, error) {
	var tv TValues

	printS("Decode BaseXX", str)

	if len(str) < Base91MinSize {
		return tv, fmt.Errorf("BaseXX string too short: %d < min=%d", len(str), Base91MinSize)
	}

	nonceAndCipherText, err := incorr.baseN.DecodeString(str)
	if err != nil {
		return tv, err
	}
	printB("Decode cipherText", nonceAndCipherText)

	if len(nonceAndCipherText) < encryptedMinSize {
		return tv, fmt.Errorf("cipherText too short: %d < min=%d", len(nonceAndCipherText), encryptedMinSize)
	}

	plainText, err := Decrypt(incorr.cipher, nonceAndCipherText)
	if err != nil {
		return tv, err
	}
	printB("Decode plainText", plainText)

	if MagicCode(plainText) != incorr.magic {
		return tv, errors.New("bad magic code")
	}

	tv, err = Unmarshal(plainText)
	printV("Decode", tv, err)
	return tv, err
}

// printS prints a string in debug mode (when doPrint is true).
func printS(name, s string) {
	if doPrint {
		n := len(s)
		if n > 30 {
			n = 30
		}
		log.Printf("DBG Incorr%s len=%d %q", name, len(s), s[:n])
	}
}

// printB prints a byte-buffer in debug mode (when doPrint is true).
func printB(name string, buf []byte) {
	if doPrint {
		n := len(buf)
		if n > 30 {
			n = 30
		}
		log.Printf("DBG Incorr%s len=%d cap=%d %x", name, len(buf), cap(buf), buf[:n])
	}
}

// printV prints TValues in debug mode (when doPrint is true).
func printV(name string, tv TValues, err error) {
	if doPrint {
		log.Printf("DBG Incorr%s tv %v %v n=%d err=%s", name,
			time.Unix(tv.Expires, 0), tv.IP, len(tv.Values), err)
	}
}
