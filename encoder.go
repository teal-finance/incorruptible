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
	"time"
)

const (
	// Base91MinSize and ciphertextMinSize need to be adapted according
	// on any change about expiry encoding size, padding size...
	Base91MinSize     = 42
	ciphertextMinSize = 6
	encryptedMinSize  = nonceSize + ciphertextMinSize + gcmTagSize

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
	printV("Encode Marshal", tv, nil)

	plaintext, err := Marshal(tv, incorr.magic)
	if err != nil {
		return "", err
	}
	printB("Encode Encrypt plaintext", plaintext)

	nonceAndCiphertextAndTag := Encrypt(incorr.cipher, plaintext)
	printB("Encode EncodeToString ciphertext", nonceAndCiphertextAndTag)

	str := incorr.baseN.EncodeToString(nonceAndCiphertextAndTag)
	printS("Encode result = BasE91", str)
	return str, nil
}

func (incorr *Incorruptible) Decode(base91 string) (TValues, error) {
	var tv TValues

	printS("Decode DecodeString BasE91", base91)

	if len(base91) < Base91MinSize {
		return tv, fmt.Errorf("BasE91 text too short: %d < min=%d", len(base91), Base91MinSize)
	}

	encrypted, err := incorr.baseN.DecodeString(base91)
	if err != nil {
		return tv, err
	}
	printB("Decode Decrypt", encrypted)

	if len(encrypted) < encryptedMinSize {
		return tv, fmt.Errorf("encrypted data too short: %d < min=%d", len(encrypted), encryptedMinSize)
	}

	plaintext, err := Decrypt(incorr.cipher, encrypted)
	if err != nil {
		return tv, err
	}
	printB("Decode Unmarshal plaintext", plaintext)

	if MagicCode(plaintext) != incorr.magic {
		return tv, errors.New("bad magic code")
	}

	tv, err = Unmarshal(plaintext)
	printV("Decode result", tv, err)
	return tv, err
}

// printS prints a string in debug mode (when doPrint is true).
func printS(name, s string) {
	if doPrint {
		n := len(s)
		if n > 30 {
			n = 30
		}
		log.Debugf("Incorr.%s len=%d %q", name, len(s), s[:n])
	}
}

// printB prints a byte-buffer in debug mode (when doPrint is true).
func printB(name string, buf []byte) {
	if doPrint {
		n := len(buf)
		if n > 30 {
			n = 30
		}
		log.Debugf("Incorr.%s len=%d cap=%d %x", name, len(buf), cap(buf), buf[:n])
	}
}

// printV prints TValues in debug mode (when doPrint is true).
func printV(name string, tv TValues, err error) {
	if doPrint {
		log.Debugf("Incorr.%s tv %v %v n=%d err=%s", name,
			time.Unix(tv.Expires, 0), tv.IP, len(tv.Values), err)
	}
}
