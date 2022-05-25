// Copyright (c) 2022 Teal.Finance contributors
// This file is part of Teal.Finance/incorruptible licensed under the MIT License.
// SPDX-License-Identifier: MIT

// Package format serialize a DToken in a short way.
// The format starts with a magic code (2 bytes),
// followed by the expiry time, the client IP, the user-defined values,
// and ends with ramdom salt as padding for a final size aligned on 32 bits.
package format

import (
	"fmt"
	"log"

	"github.com/teal-finance/incorruptible/dtoken"
	"github.com/teal-finance/incorruptible/format/coding"

	"github.com/klauspost/compress/s2"
	rand "github.com/zhangyunhao116/fastrand"
)

const (
	enablePadding  = false
	paddingStep    = 8
	paddingMaxSize = 3 * paddingStep // result must be less than 256 bytes

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

func newSerializer(dt dtoken.DToken) (s Serializer) {
	s.ipLength = len(dt.IP) // can be 0, 4 or 16

	s.nValues = len(dt.Values)

	s.valTotalSize = s.nValues
	for _, v := range dt.Values {
		s.valTotalSize += len(v)
	}

	s.payloadSize = coding.ExpirySize + s.ipLength + s.valTotalSize

	s.compressed = doesCompress(s.payloadSize)

	return s
}

// doesCompress decides to compress or not the payload.
// The compression decision is a bit randomized
// to limit the "chosen plaintext" attack.
func doesCompress(payloadSize int) bool {
	switch {
	case payloadSize < sizeMayCompress:
		return false
	case payloadSize < sizeMustCompress:
		return (0 == rand.Intn(1))
	default:
		return true
	}
}

func Marshal(dt dtoken.DToken, magic uint8) ([]byte, error) {
	s := newSerializer(dt)

	b, err := s.putHeaderExpiryIP(magic, dt)
	if err != nil {
		return nil, err
	}

	b, err = s.appendValues(b, dt)
	if err != nil {
		return nil, err
	}
	if len(b) != coding.HeaderSize+s.payloadSize {
		return nil, fmt.Errorf("unexpected length got=%d want=%d", len(b), coding.HeaderSize+s.payloadSize)
	}

	if s.compressed {
		c := s2.Encode(nil, b[coding.HeaderSize:])
		n := copy(b[coding.HeaderSize:], c)
		if n != len(c) {
			return nil, fmt.Errorf("unexpected copied bytes got=%d want=%d", n, len(c))
		}
		b = b[:coding.HeaderSize+n]
	}

	if enablePadding {
		b = s.appendPadding(b)
	}

	return b, nil
}

func (s Serializer) allocateBuffer() []byte {
	length := coding.HeaderSize + coding.ExpirySize
	capacity := length + s.ipLength + s.valTotalSize

	if enablePadding {
		capacity += paddingMaxSize
	}

	return make([]byte, length, capacity)
}

func (s Serializer) putHeaderExpiryIP(magic uint8, dt dtoken.DToken) ([]byte, error) {
	b := s.allocateBuffer()

	m, err := coding.NewMetadata(s.ipLength, s.compressed, s.nValues)
	if err != nil {
		return nil, err
	}

	m.PutHeader(b, magic)

	err = coding.PutExpiry(b, dt.Expiry)
	if err != nil {
		return nil, err
	}

	b = coding.AppendIP(b, dt.IP)

	return b, nil
}

func (s Serializer) appendValues(b []byte, dt dtoken.DToken) ([]byte, error) {
	for _, v := range dt.Values {
		if len(v) > 255 {
			return nil, fmt.Errorf("too large %d > 255", v)
		}
		b = append(b, uint8(len(v)))
		b = append(b, v...)
	}
	return b, nil
}

// appendPadding adds random padding bytes.
func (s *Serializer) appendPadding(b []byte) []byte {
	trailing := len(b) % paddingStep
	missing := paddingStep - trailing
	missing += paddingStep * rand.Intn(paddingMaxSize/paddingStep-1)

	for i := 1; i < missing; i++ {
		b = append(b, uint8(rand.Intn(256)))
	}

	if missing > 255 {
		log.Panic("cannot append more than 255 padding bytes got=", missing)
	}

	// last byte is the padding length
	b = append(b, uint8(missing))

	return b
}
