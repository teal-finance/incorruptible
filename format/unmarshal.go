// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

package format

import (
	"fmt"
	"log"

	"github.com/klauspost/compress/s2"

	"github.com/teal-finance/incorruptible/dtoken"
	"github.com/teal-finance/incorruptible/format/coding"
)

const doPrint = false

func Unmarshal(buf []byte) (dtoken.DToken, error) {
	printDebug("Unmarshal", buf)

	if len(buf) < coding.HeaderSize+coding.ExpirySize {
		return dtoken.DToken{}, fmt.Errorf("not enough bytes (%d) for header+expiry", len(buf))
	}

	meta := coding.GetMetadata(buf)
	buf = buf[coding.HeaderSize:] // drop header

	printDebug("Unmarshal Metadata", buf)

	if EnablePadding {
		var err error
		buf, err = dropPadding(buf)
		if err != nil {
			return dtoken.DToken{}, err
		}
		printDebug("Unmarshal Padding", buf)
	}

	if meta.IsCompressed() {
		var err error
		buf, err = s2.Decode(nil, buf)
		if err != nil {
			return dtoken.DToken{}, fmt.Errorf("s2.Decode %w", err)
		}
		printDebug("Unmarshal Uncompress", buf)
	}

	if len(buf) < meta.PayloadMinSize() {
		return dtoken.DToken{}, fmt.Errorf("not enough bytes for payload %d < %d", len(buf), meta.PayloadMinSize())
	}

	var dt dtoken.DToken
	buf, dt.Expiry = coding.DecodeExpiry(buf)
	buf, dt.IP = meta.DecodeIP(buf)

	printDebug("Unmarshal Expiry IP", buf)

	var err error
	dt.Values, err = parseValues(buf, meta.NValues())
	if err != nil {
		return dt, err
	}

	printDebug("Unmarshal Values", buf)

	return dt, nil
}

func parseValues(buf []byte, nV int) ([][]byte, error) {
	values := make([][]byte, 0, nV)

	for i := 0; i < nV; i++ {
		if len(buf) < (nV - i) {
			return nil, fmt.Errorf("not enough bytes (%d) at length #%d", len(buf), i)
		}

		size := buf[0] // number of bytes representing the value
		buf = buf[1:]  // drop the byte containing the length of the value

		if len(buf) < int(size) {
			return nil, fmt.Errorf("not enough bytes (%d) at value #%d", len(buf), i)
		}

		v := buf[:size]  // extract the value in raw form
		buf = buf[size:] // drop the bytes containing the value

		values = append(values, v)
	}

	if len(buf) > 0 {
		return nil, fmt.Errorf("unexpected remaining %d bytes", len(buf))
	}

	return values, nil
}

func dropPadding(buf []byte) ([]byte, error) {
	paddingSize := int(buf[len(buf)-1]) // last byte is the padding length
	if paddingSize > paddingMaxSize {
		return nil, fmt.Errorf("too much padding bytes (%d)", paddingSize)
	}

	buf = buf[:len(buf)-paddingSize] // drop padding
	return buf, nil
}

func printDebug(name string, buf []byte) {
	if doPrint {
		log.Printf("Incorr%s len=%d", name, len(buf))
	}
}
