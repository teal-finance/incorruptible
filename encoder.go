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

	"github.com/teal-finance/incorruptible/format"
	"github.com/teal-finance/incorruptible/format/coding"
	"github.com/teal-finance/incorruptible/tvalues"
)

const (
	Base91MinSize     = 27
	ciphertextMinSize = 22

	// no space, no double-quote ", no semi-colon ; and no back-slash \.
	noSpaceDoubleQuoteSemicolon = "" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789!#$%&()*+,-./:<=>?@[]^_`{|}~'"

	doPrint = false
)

func (incorr *Incorruptible) Encode(tv tvalues.TValues) (string, error) {
	printV("Encode", tv, errors.New(""))

	plainText, err := format.Marshal(tv, incorr.magic)
	if err != nil {
		return "", err
	}
	printB("Encode plaintext", plainText)

	cipherText := incorr.cipher.Encrypt(plainText)
	printB("Encode ciphertext", cipherText)

	str := incorr.baseN.EncodeToString(cipherText)
	printS("Encode BaseXX", str)
	return str, nil
}

func (incorr *Incorruptible) Decode(str string) (tvalues.TValues, error) {
	printS("Decode BaseXX", str)

	var tv tvalues.TValues
	if len(str) < Base91MinSize {
		return tv, fmt.Errorf("BaseXX string too short: %d < min=%d", len(str), Base91MinSize)
	}

	cipherText, err := incorr.baseN.DecodeString(str)
	if err != nil {
		return tv, err
	}
	printB("Decode cipherText", cipherText)

	if len(cipherText) < ciphertextMinSize {
		return tv, fmt.Errorf("cipherText too short: %d < min=%d", len(cipherText), ciphertextMinSize)
	}

	plainText, err := incorr.cipher.Decrypt(cipherText)
	if err != nil {
		return tv, err
	}
	printB("Decode plainText", plainText)

	magic := coding.MagicCode(plainText)
	if magic != incorr.magic {
		return tv, errors.New("bad magic code")
	}

	tv, err = format.Unmarshal(plainText)
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
		log.Printf("Incorr%s len=%d %q", name, len(s), s[:n])
	}
}

// printB prints a byte-buffer in debug mode (when doPrint is true).
func printB(name string, buf []byte) {
	if doPrint {
		n := len(buf)
		if n > 30 {
			n = 30
		}
		log.Printf("Incorr%s len=%d cap=%d %x", name, len(buf), cap(buf), buf[:n])
	}
}

// printV prints TValues in debug mode (when doPrint is true).
func printV(name string, tv tvalues.TValues, err error) {
	if doPrint {
		log.Printf("Incorr%s tv %v %v n=%d err=%s", name,
			time.Unix(tv.Expires, 0), tv.IP, len(tv.Values), err)
	}
}
