// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

package incorruptible

import (
	"fmt"
	"math/rand"
)

const (
	EnablePadding  = false
	paddingStep    = 8
	paddingMaxSize = 3 * paddingStep // result must be less than 256 bytes
)

// appendPadding adds a random number of random padding bytes.
//
//nolint:gosec // strong random generator not required for padding
func (s *Serializer) appendPadding(buf []byte) []byte {
	// computes the number of trailing bytes to fill the padding
	trailing := len(buf) % paddingStep
	adding := paddingStep - trailing - 1 // -1 = last byte encodes the padding size (minus one)

	// adds more padding bytes
	random := rand.Int63() & (paddingMaxSize/paddingStep - 1)
	adding += paddingStep * int(random)

	if adding > 255 {
		log.Panic("Cannot store the padding bytes in a byte got=", adding)
	}

	oldSize := len(buf)
	newSize := len(buf) + adding
	if cap(buf) < newSize {
		log.Panic("Preallocated Buffer has incorrect cap=", cap(buf), "want=", newSize)
	}

	// increase the buffer length
	buf = buf[:newSize]
	_, err := rand.Read(buf[oldSize:newSize])
	if err != nil {
		log.Error("Incorruptible appendPadding ", err)
	}

	// the last byte stores the padding size
	buf = append(buf, uint8(adding))

	if (len(buf) % paddingStep) != 0 {
		log.Panicf("Final len=%d should be a multiple of paddingStep=%d but modulo=%d",
			len(buf), paddingStep, len(buf)%paddingStep)
	}

	return buf
}

func dropPadding(buf []byte) ([]byte, error) {
	paddingSizeMinusOne := int(buf[len(buf)-1]) // last byte encodes the padding size minus one
	if paddingSizeMinusOne > paddingMaxSize {
		return nil, fmt.Errorf("too much padding bytes (%d)", paddingSizeMinusOne)
	}

	// drop the padding and also the last byte containing the padding size
	buf = buf[:len(buf)-paddingSizeMinusOne-1]
	return buf, nil
}
