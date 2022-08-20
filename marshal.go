// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

package incorruptible

import (
	"fmt"
	"math/rand"

	"github.com/klauspost/compress/s2"
)

const (
	sizeMayCompress  = 50 // by experience, cannot be below than 24 bytes
	sizeMustCompress = 99
)

type Serializer struct {
	ipLength     int
	nValues      int // number of values
	valTotalSize int // sum of the value lengths
	payloadSize  int // size in bytes of the uncompressed payload
	compressed   bool
}

func newSerializer(tv TValues) Serializer {
	var s Serializer

	s.ipLength = len(tv.IP) // can be 0, 4 or 16

	s.nValues = len(tv.Values)

	s.valTotalSize = s.nValues
	for _, v := range tv.Values {
		s.valTotalSize += len(v)
	}

	s.payloadSize = ExpirySize + s.ipLength + s.valTotalSize

	s.compressed = doesCompress(s.payloadSize)

	return s
}

// doesCompress decides to compress or not the payload.
// The compression decision is a bit randomized
// to limit the "chosen plaintext" attack.
//
//nolint:gosec // strong random generator not required here
func doesCompress(payloadSize int) bool {
	switch {
	case payloadSize < sizeMayCompress:
		return false
	case payloadSize < sizeMustCompress:
		zeroOrOne := (rand.Int63() & 1)
		return (zeroOrOne == 0)
	default:
		return true
	}
}

// Marshal serializes a TValues in a short way.
// The format starts with a magic code (2 bytes),
// followed by the expiry time, the client IP, the user-defined values,
// and ends with random salt as padding for a final size aligned on 32 bits.
func Marshal(tv TValues, magic uint8) ([]byte, error) {
	s := newSerializer(tv)

	b, err := s.putHeaderExpiryIP(magic, tv)
	if err != nil {
		return nil, err
	}

	b, err = s.appendValues(b, tv)
	if err != nil {
		return nil, err
	}
	if len(b) != HeaderSize+s.payloadSize {
		return nil, fmt.Errorf("unexpected length got=%d want=%d", len(b), HeaderSize+s.payloadSize)
	}

	if s.compressed {
		c := s2.Encode(nil, b[HeaderSize:])
		n := copy(b[HeaderSize:], c)
		if n != len(c) {
			return nil, fmt.Errorf("unexpected copied bytes got=%d want=%d", n, len(c))
		}
		b = b[:HeaderSize+n]
	}

	if EnablePadding {
		b = s.appendPadding(b)
	}

	return b, nil
}

func (s Serializer) allocateBuffer() []byte {
	length := HeaderSize + ExpirySize
	capacity := length + s.ipLength + s.valTotalSize

	if EnablePadding {
		capacity += paddingMaxSize
	}

	return make([]byte, length, capacity)
}

func (s Serializer) putHeaderExpiryIP(magic uint8, tv TValues) ([]byte, error) {
	b := s.allocateBuffer()

	m, err := NewMetadata(s.ipLength, s.compressed, s.nValues)
	if err != nil {
		return nil, err
	}

	m.PutHeader(b, magic)

	err = PutExpiry(b, tv.Expires)
	if err != nil {
		return nil, err
	}

	b = AppendIP(b, tv.IP)

	return b, nil
}

func (s Serializer) appendValues(buf []byte, tv TValues) ([]byte, error) {
	for _, v := range tv.Values {
		if len(v) > 255 {
			return nil, fmt.Errorf("too large %d > 255", v)
		}
		buf = append(buf, uint8(len(v)))
		buf = append(buf, v...)
	}
	return buf, nil
}
