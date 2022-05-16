// Copyright (c) 2022 Teal.Finance contributors
// This file is part of Teal.Finance/incorruptible licensed under the MIT License.
// SPDX-License-Identifier: MIT

package incorruptible

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/teal-finance/incorruptible/dtoken"
	"github.com/teal-finance/incorruptible/format"
	"github.com/teal-finance/incorruptible/format/coding"
)

const (
	base92MinSize     = 26
	ciphertextMinSize = 22

	// no space, no double-quote ", no semi-colon ; and no back-slash \.
	noSpaceDoubleQuoteSemicolon = "" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789!#$%&()*+,-./:<=>?@[]^_`{|}~'"

	doPrint = false
)

func (s *Session) Encode(dt dtoken.DToken) (string, error) {
	printDT("Encode", dt, errors.New(""))

	plaintext, err := format.Marshal(dt, s.magic)
	if err != nil {
		return "", err
	}
	printBin("Encode plaintext", plaintext)

	ciphertext := s.cipher.Encrypt(plaintext)
	printBin("Encode ciphertext", ciphertext)

	str := s.baseN.EncodeToString(ciphertext)
	printStr("Encode BaseXX", str)
	return str, nil
}

func (s *Session) Decode(str string) (dtoken.DToken, error) {
	printStr("Decode BaseXX", str)

	var dt dtoken.DToken
	if len(str) < base92MinSize {
		return dt, fmt.Errorf("BaseXX string too short: %d < min=%d", len(str), base92MinSize)
	}

	ciphertext, err := s.baseN.DecodeString(str)
	if err != nil {
		return dt, err
	}
	printBin("Decode ciphertext", ciphertext)

	if len(ciphertext) < ciphertextMinSize {
		return dt, fmt.Errorf("ciphertext too short: %d < min=%d", len(ciphertext), ciphertextMinSize)
	}

	plaintext, err := s.cipher.Decrypt(ciphertext)
	if err != nil {
		return dt, err
	}
	printBin("Decode plaintext", plaintext)

	magic := coding.MagicCode(plaintext)
	if magic != s.magic {
		return dt, errors.New("bad magic code")
	}

	dt, err = format.Unmarshal(plaintext)
	printDT("Decode", dt, err)
	return dt, err
}

func printStr(name, s string) {
	if doPrint {
		n := len(s)
		if n > 30 {
			n = 30
		}
		log.Printf("Session%s len=%d %q", name, len(s), s[:n])
	}
}

func printBin(name string, b []byte) {
	if doPrint {
		n := len(b)
		if n > 30 {
			n = 30
		}
		log.Printf("Session%s len=%d cap=%d %x", name, len(b), cap(b), b[:n])
	}
}

func printDT(name string, dt dtoken.DToken, err error) {
	if doPrint {
		log.Printf("Session%s dt %v %v n=%d err=%s", name,
			time.Unix(dt.Expiry, 0), dt.IP, len(dt.Values), err)
	}
}
