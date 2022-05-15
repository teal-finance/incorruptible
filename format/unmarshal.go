// Copyright (c) 2022 Teal.Finance contributors
// Licensed under the EUPL either v1.2 or any later version, at the licensee's option.
// SPDX-License-Identifier: EUPL-1.2+
// See the LICENCE.md file or https://joinup.ec.europa.eu/page/eupl-text-11-12
// This file is part of Teal.Finance/Incorruptible, a tiny cookie token.

package format

import (
	"fmt"
	"log"

	"github.com/klauspost/compress/s2"

	"github.com/teal-finance/incorruptible/dtoken"
	"github.com/teal-finance/incorruptible/format/coding"
)

const doPrint = false

func Unmarshal(b []byte) (dt dtoken.DToken, err error) {
	printDebug("Unmarshal", b)

	if len(b) < coding.HeaderSize+coding.ExpirySize {
		return dt, fmt.Errorf("not enough bytes (%d) for header+expiry", len(b))
	}

	m := coding.GetMetadata(b)
	b = b[coding.HeaderSize:] // drop header

	printDebug("Unmarshal Metadata", b)

	if enablePadding {
		b, err = dropPadding(b)
		if err != nil {
			return dt, err
		}
		printDebug("Unmarshal Padding", b)
	}

	if m.IsCompressed() {
		b, err = s2.Decode(nil, b)
		if err != nil {
			return dt, fmt.Errorf("s2.Decode %w", err)
		}
		printDebug("Unmarshal Uncompress", b)
	}

	if len(b) < m.PayloadMinSize() {
		return dt, fmt.Errorf("not enough bytes for payload %d < %d", len(b), m.PayloadMinSize())
	}

	b, dt.Expiry = coding.DecodeExpiry(b)
	b, dt.IP = m.DecodeIP(b)

	printDebug("Unmarshal Expiry IP", b)

	dt.Values, err = parseValues(b, m.NValues())
	if err != nil {
		return dt, err
	}

	printDebug("Unmarshal Values", b)

	return dt, nil
}

func parseValues(b []byte, nV int) ([][]byte, error) {
	values := make([][]byte, 0, nV)

	for i := 0; i < nV; i++ {
		if len(b) < (nV - i) {
			return nil, fmt.Errorf("not enough bytes (%d) at length #%d", len(b), i)
		}

		n := b[0] // number of bytes representing the value
		b = b[1:] // drop the byte containing the length of the value

		if len(b) < int(n) {
			return nil, fmt.Errorf("not enough bytes (%d) at value #%d", len(b), i)
		}

		v := b[:n] // extract the value in raw form
		b = b[n:]  // drop the bytes containing the value

		values = append(values, v)
	}

	if len(b) > 0 {
		return nil, fmt.Errorf("unexpected remaining %d bytes", len(b))
	}

	return values, nil
}

func dropPadding(b []byte) ([]byte, error) {
	paddingSize := int(b[len(b)-1]) // last byte is the padding length
	if paddingSize > paddingMaxSize {
		return nil, fmt.Errorf("too much padding bytes (%d)", paddingSize)
	}

	b = b[:len(b)-paddingSize] // drop padding
	return b, nil
}

func printDebug(name string, b []byte) {
	if doPrint {
		log.Printf("Session%s len=%d", name, len(b))
	}
}
