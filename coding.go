// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

package incorruptible

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

func MagicCode(buf []byte) uint8 {
	return buf[0]
}

type Metadata byte

func GetMetadata(buf []byte) Metadata {
	return Metadata(buf[2])
}

// NewMetadata sets the metadata bits within the token.
func NewMetadata(ipLength int, compressed bool, nValues int) (Metadata, error) {
	var meta byte

	switch ipLength {
	case 0:
		meta = 0
	case 4:
		meta = maskIP | maskIPv4
	case 16:
		meta = maskIP
	default:
		return 0, fmt.Errorf("unexpected IP length %d", ipLength)
	}

	if compressed {
		meta |= maskCompress
	}

	if nValues < 0 {
		return 0, fmt.Errorf("negative nValues %d", nValues)
	}
	if nValues > MaxValues {
		return 0, fmt.Errorf("too much values %d > %d", nValues, MaxValues)
	}

	meta |= uint8(nValues)

	return Metadata(meta), nil
}

func (meta Metadata) PayloadMinSize() int {
	return ExpirySize + meta.ipLength() + meta.NValues()
}

// PutHeader fills the magic code, the salt and the metadata.
//
// "math/rand" is 40 times faster than "crypto/rand"
// see: https://github.com/SimonWaldherr/golang-benchmarks#random
//
//nolint:gosec // strong random generator not required here
func (meta Metadata) PutHeader(buf []byte, magic uint8) {
	buf[0] = magic
	buf[1] = byte(rand.Int63()) // random salt
	buf[2] = byte(meta)
}

func (meta Metadata) ipLength() int {
	if (meta & maskIPv4) != 0 {
		return net.IPv4len
	}
	if (meta & maskIP) != 0 {
		return net.IPv6len
	}
	return 0
}

func (meta Metadata) IsCompressed() bool {
	c := meta & maskCompress
	return c != 0
}

func (meta Metadata) NValues() int {
	n := meta & maskNValues
	return int(n)
}

func PutExpiry(buf []byte, unix int64) error {
	internal, err := unixToInternalExpiry(unix)
	if err != nil {
		return err
	}

	putInternalExpiry(buf, internal)

	return nil
}

func DecodeExpiry(buf []byte) ([]byte, int64) {
	internal := internalExpiry(buf)
	unix := internalExpiryToUnix(internal)
	return buf[ExpirySize:], unix
}

func AppendIP(buf []byte, ip net.IP) []byte {
	return append(buf, ip...)
}

func (meta Metadata) DecodeIP(buf []byte) ([]byte, net.IP) {
	n := meta.ipLength()
	ip := buf[:n]
	return buf[n:], ip
}

// Uint64ToBytes works on the byte-level encoding of the Incorruptible token.
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

func BytesToUint64(buf []byte) (uint64, error) {
	var ret uint64
	switch len(buf) {
	default:
		return 0, fmt.Errorf("too much bytes (length=%d) to extract an Uint64 (4 bytes)", len(buf))
	case 8:
		ret |= uint64(buf[7]) << 56
		fallthrough
	case 7:
		ret |= uint64(buf[6]) << 48
		fallthrough
	case 6:
		ret |= uint64(buf[5]) << 40
		fallthrough
	case 5:
		ret |= uint64(buf[4]) << 32
		fallthrough
	case 4:
		ret |= uint64(buf[3]) << 24
		fallthrough
	case 3:
		ret |= uint64(buf[2]) << 16
		fallthrough
	case 2:
		ret |= uint64(buf[1]) << 8
		fallthrough
	case 1:
		return ret | uint64(buf[0]), nil
	case 0:
		return 0, nil
	}
}
