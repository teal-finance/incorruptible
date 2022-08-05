// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

// Package format serialize a TValues in a short way.
// The format starts with a magic code (2 bytes),
// followed by the expiry time, the client IP, the user-defined values,
// and ends with random salt as padding for a final size aligned on 32 bits.
package format

import (
	"fmt"
	"log"

	"github.com/klauspost/compress/s2"
	rand "github.com/zhangyunhao116/fastrand"

	"github.com/teal-finance/incorruptible/format/coding"
	"github.com/teal-finance/incorruptible/tvalues"
)

const (
	EnablePadding  = false
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

func newSerializer(tv tvalues.TValues) Serializer {
	var s Serializer

	s.ipLength = len(tv.IP) // can be 0, 4 or 16

	s.nValues = len(tv.Values)

	s.valTotalSize = s.nValues
	for _, v := range tv.Values {
		s.valTotalSize += len(v)
	}

	s.payloadSize = coding.ExpirySize + s.ipLength + s.valTotalSize

	s.compressed = doesCompress(s.payloadSize)

	return s
}

// doesCompress decides to compress or not the payload.
// The compression decision is a bit randomized
// to limit the "chosen plainText" attack.
func doesCompress(payloadSize int) bool {
	switch {
	case payloadSize < sizeMayCompress:
		return false
	case payloadSize < sizeMustCompress:
		return (rand.Intn(1) == 0)
	default:
		return true
	}
}

func Marshal(tv tvalues.TValues, magic uint8) ([]byte, error) {
	s := newSerializer(tv)

	b, err := s.putHeaderExpiryIP(magic, tv)
	if err != nil {
		return nil, err
	}

	b, err = s.appendValues(b, tv)
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

	if EnablePadding {
		b = s.appendPadding(b)
	}

	return b, nil
}

func (s Serializer) allocateBuffer() []byte {
	length := coding.HeaderSize + coding.ExpirySize
	capacity := length + s.ipLength + s.valTotalSize

	if EnablePadding {
		capacity += paddingMaxSize
	}

	return make([]byte, length, capacity)
}

func (s Serializer) putHeaderExpiryIP(magic uint8, tv tvalues.TValues) ([]byte, error) {
	b := s.allocateBuffer()

	m, err := coding.NewMetadata(s.ipLength, s.compressed, s.nValues)
	if err != nil {
		return nil, err
	}

	m.PutHeader(b, magic)

	err = coding.PutExpiry(b, tv.Expires)
	if err != nil {
		return nil, err
	}

	b = coding.AppendIP(b, tv.IP)

	return b, nil
}

func (s Serializer) appendValues(buf []byte, tv tvalues.TValues) ([]byte, error) {
	for _, v := range tv.Values {
		if len(v) > 255 {
			return nil, fmt.Errorf("too large %d > 255", v)
		}
		buf = append(buf, uint8(len(v)))
		buf = append(buf, v...)
	}
	return buf, nil
}

// appendPadding adds random padding bytes.
func (s *Serializer) appendPadding(buf []byte) []byte {
	trailing := len(buf) % paddingStep
	missing := paddingStep - trailing
	missing += paddingStep * rand.Intn(paddingMaxSize/paddingStep-1)

	for i := 1; i < missing; i++ {
		buf = append(buf, uint8(rand.Intn(256)))
	}

	if missing > 255 {
		log.Panic("cannot append more than 255 padding bytes got=", missing)
	}

	// last byte is the padding length
	buf = append(buf, uint8(missing))

	return buf
}
