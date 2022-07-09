// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

package coding

import (
	"fmt"
	"time"
)

const (
	// The expiry is stored in 3 bytes, with a 30 seconds precision, starting from 2022.
	ExpiryStartYear = 2022
	ExpiryMaxYear   = ExpiryStartYear + rangeInYears

	ExpirySize = 3 // 24 bits = 10 years with 20-second precision
	expiryBits = ExpirySize * 8
	expiryMax  = 1 << expiryBits

	PrecisionInSeconds     = 20
	rangeInSeconds     int = expiryMax * PrecisionInSeconds
	rangeInYears           = rangeInSeconds / secondsPerYear

	internalToUnix = (ExpiryStartYear - 1970) * secondsPerYear
	unixToInternal = -internalToUnix

	secondsPerMinute = 60
	secondsPerHour   = 60 * secondsPerMinute
	secondsPerDay    = 24 * secondsPerHour      // = 86400
	secondsPerYear   = 365.2425 * secondsPerDay // = 31556952 = average including leap years
)

// unixToInternalExpiry converts Unix time to the internal 3-byte coding.
func unixToInternalExpiry(unix int64) (uint32, error) {
	if unix == 0 {
		return 0, nil
	}

	secondsSinceInternalStarYear := unix + unixToInternal
	expiry := secondsSinceInternalStarYear / PrecisionInSeconds

	if expiry < 0 {
		return 0, fmt.Errorf("unix time too low (%d s) %s < %d (internal=%d)", unix, time.Unix(unix, 0), ExpiryStartYear, expiry)
	}
	if expiry >= expiryMax {
		return 0, fmt.Errorf("unix time too high (%d s) %s > %d (internal=%d)", unix, time.Unix(unix, 0), ExpiryMaxYear, expiry)
	}

	return uint32(expiry), nil
}

// internalExpiryToUnix converts the internal expiry to Unix time format: seconds since epoch (1970 UTC).
func internalExpiryToUnix(expiry uint32) int64 {
	if expiry == 0 {
		return 0
	}

	seconds := int64(expiry) * PrecisionInSeconds
	unix := seconds + internalToUnix
	return unix
}

func putInternalExpiry(buf []byte, e uint32) {
	// Expiry is store just after the header
	buf[HeaderSize+0] = byte(e)
	buf[HeaderSize+1] = byte(e >> 8)
	if ExpirySize >= 3 {
		buf[HeaderSize+2] = byte(e >> 16)
	}
	if ExpirySize >= 4 {
		buf[HeaderSize+3] = byte(e >> 24)
	}
}

func internalExpiry(buf []byte) uint32 {
	e := uint32(buf[0])
	e |= uint32(buf[1]) << 8
	if ExpirySize >= 3 {
		e |= uint32(buf[2]) << 16
	}
	if ExpirySize >= 4 {
		e |= uint32(buf[3]) << 24
	}
	return e
}
