// Copyright (c) 2022 Teal.Finance contributors
// This file is part of Teal.Finance/Incorruptible, a tiny cookie token.
// SPDX-License-Identifier: LGPL-3.0-or-later
// Teal.Finance/Incorruptible is free software under the GNU LGPL
// either version 3 or any later version, at the licensee's option.
// See the LICENSE file or <https://www.gnu.org/licenses/lgpl-3.0.html>

// Package coding works on the byte encoding low-level.
package coding

import (
	"fmt"
	"math/rand"
	"net"
)

const (
	HeaderSize    = magicCodeSize + saltSize + metadataSize
	magicCodeSize = 1
	saltSize      = 1
	metadataSize  = 1

	// Metadata coding in byte #2.
	maskIP       = 0b_1000_0000
	maskIPv4     = 0b_0100_0000
	maskCompress = 0b_0010_0000
	maskNValues  = 0b_0001_1111

	MaxValues int = maskNValues
)

func MagicCode(b []byte) uint8 {
	return b[0]
}

type Metadata byte

func GetMetadata(b []byte) Metadata {
	return Metadata(b[2])
}

func NewMetadata(ipLength int, compressed bool, nValues int) (Metadata, error) {
	var m byte

	switch ipLength {
	case 0:
		m = 0
	case 4:
		m = maskIP | maskIPv4
	case 16:
		m = maskIP
	default:
		return 0, fmt.Errorf("unexpected IP length %d", ipLength)
	}

	if compressed {
		m |= maskCompress
	}

	if nValues < 0 {
		return 0, fmt.Errorf("negative nValues %d", nValues)
	}
	if nValues > MaxValues {
		return 0, fmt.Errorf("too much values %d > %d", nValues, MaxValues)
	}

	m |= uint8(nValues)

	return Metadata(m), nil
}

func (m Metadata) PayloadMinSize() int {
	return ExpirySize + m.ipLength() + m.NValues()
}

// putHeader fills the magic code, the salt and the metadata.
func (m Metadata) PutHeader(b []byte, magic uint8) {
	b[0] = magic
	b[1] = byte(rand.Intn(256)) // random salt
	b[2] = byte(m)
}

func (m Metadata) ipLength() int {
	if (m & maskIPv4) != 0 {
		return net.IPv4len
	}
	if (m & maskIP) != 0 {
		return net.IPv6len
	}
	return 0
}

func (m Metadata) IsCompressed() bool {
	c := m & maskCompress
	return c != 0
}

func (m Metadata) NValues() int {
	n := m & maskNValues
	return int(n)
}

func PutExpiry(b []byte, unix int64) error {
	internal, err := unixToInternalExpiry(unix)
	if err != nil {
		return err
	}

	putInternalExpiry(b, internal)

	return nil
}

func DecodeExpiry(b []byte) ([]byte, int64) {
	internal := internalExpiry(b)
	unix := internalExpiryToUnix(internal)
	return b[ExpirySize:], unix
}

func AppendIP(b []byte, ip net.IP) []byte {
	return append(b, ip...)
}

func (m Metadata) DecodeIP(b []byte) ([]byte, net.IP) {
	n := m.ipLength()
	ip := b[:n]
	return b[n:], ip
}

func Uint64ToBytes(v uint64) []byte {
	switch {
	case v == 0:
		return nil
	case v < (1 << 8):
		return []byte{byte(v)}
	case v < (1 << 16):
		return []byte{byte(v), byte(v >> 8)}
	case v < (1 << 24):
		return []byte{byte(v), byte(v >> 8), byte(v >> 16)}
	case v < (1 << 32):
		return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
	case v < (1 << 40):
		return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24), byte(v >> 32)}
	case v < (1 << 48):
		return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24), byte(v >> 32), byte(v >> 40)}
	case v < (1 << 56):
		return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24), byte(v >> 32), byte(v >> 40), byte(v >> 48)}
	default:
		return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24), byte(v >> 32), byte(v >> 40), byte(v >> 48), byte(v >> 56)}
	}
}

func BytesToUint64(b []byte) (uint64, error) {
	var r uint64
	switch len(b) {
	default:
		return 0, fmt.Errorf("too much bytes (length=%d) to extract an Uint64 (4 bytes)", len(b))
	case 8:
		r |= uint64(b[7]) << 56
		fallthrough
	case 7:
		r |= uint64(b[6]) << 48
		fallthrough
	case 6:
		r |= uint64(b[5]) << 40
		fallthrough
	case 5:
		r |= uint64(b[4]) << 32
		fallthrough
	case 4:
		r |= uint64(b[3]) << 24
		fallthrough
	case 3:
		r |= uint64(b[2]) << 16
		fallthrough
	case 2:
		r |= uint64(b[1]) << 8
		fallthrough
	case 1:
		return r | uint64(b[0]), nil
	case 0:
		return 0, nil
	}
}
