// Copyright (c) 2022 Teal.Finance contributors
// This file is part of Teal.Finance/Incorruptible, a tiny cookie token.
// SPDX-License-Identifier: LGPL-3.0-or-later
// Teal.Finance/Incorruptible is free software under the GNU LGPL
// either version 3 or any later version, at the licensee's option.
// See the LICENSE file or <https://www.gnu.org/licenses/lgpl-3.0.html>

// Package token represents the decoded form of a "session" token.
package dtoken

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/teal-finance/incorruptible/format/coding"
)

const (
	secondsPerMinute = 60
	secondsPerHour   = 60 * secondsPerMinute
	secondsPerDay    = 24 * secondsPerHour      // = 86400
	secondsPerYear   = 365.2425 * secondsPerDay // = 31556952 = average including leap years
)

type DToken struct {
	Expiry int64 // Unix time UTC (seconds since 1970)
	IP     net.IP
	Values [][]byte
}

func (dt *DToken) SetExpiry(d time.Duration) {
	dt.Expiry = time.Now().Add(d).Unix()
}

func (dt DToken) ExpiryTime() time.Time {
	return time.Unix(dt.Expiry, 0)
}

func (dt *DToken) SetRemoteIP(r *http.Request) error {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return fmt.Errorf("setting IP but %w", err)
	}
	dt.IP = net.ParseIP(ip)
	dt.ShortenIP()
	return nil
}

func (dt DToken) Valid(r *http.Request) error {
	if !dt.ValidExpiry() {
		return fmt.Errorf("expired or malformed or date in the far future: %ds %v",
			dt.Expiry, time.Unix(dt.Expiry, 0))
	}

	return dt.ValidIP(r)
}

func (dt DToken) ValidExpiry() bool {
	if dt.Expiry == 0 {
		return true
	}
	c := dt.CompareExpiry()
	return (c == 0)
}

func (dt DToken) ValidIP(r *http.Request) error {
	if len(dt.IP) == 0 {
		return nil // anonymous token without IP
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return fmt.Errorf("checking token but %w", err)
	}
	if !dt.IP.Equal(net.ParseIP(ip)) {
		return fmt.Errorf("token says IP=%v but got %v", dt.IP, ip)
	}

	return nil
}

func (dt *DToken) ShortenIP() {
	if dt.IP == nil {
		return
	}
	if v4 := dt.IP.To4(); v4 != nil {
		dt.IP = v4
	}
}

func (dt DToken) CompareExpiry() int {
	now := time.Now().Unix()
	if dt.Expiry < now {
		return -1
	}
	if dt.Expiry > now+secondsPerYear {
		return 1
	}
	return 0
}

func (dt *DToken) SetUint64(i int, v uint64) error {
	if err := dt.check(i); err != nil {
		return err
	}
	b := coding.Uint64ToBytes(v)
	dt.set(i, b)
	return nil
}

func (dt DToken) Uint64(i int) (uint64, error) {
	if (i < 0) || (i >= len(dt.Values)) {
		return 0, fmt.Errorf("i=%d out of range (%d values)", i, len(dt.Values))
	}
	return coding.BytesToUint64(dt.Values[i])
}

func (dt *DToken) SetBool(i int, value bool) error {
	if err := dt.check(i); err != nil {
		return err
	}

	var b []byte // false --> length=0
	if value {
		b = []byte{0} // true --> length=1
	}

	dt.set(i, b)
	return nil
}

func (dt DToken) Bool(i int) (bool, error) {
	if (i < 0) || (i >= len(dt.Values)) {
		return false, fmt.Errorf("i=%d out of range (%d values)", i, len(dt.Values))
	}

	b := dt.Values[i]

	switch len(b) {
	default:
		return false, fmt.Errorf("too much bytes (length=%d) for a boolean", len(b))
	case 1:
		return true, nil
	case 0:
		return false, nil
	}
}

func (dt *DToken) SetString(i int, s string) error {
	if err := dt.check(i); err != nil {
		return err
	}

	dt.set(i, []byte(s))
	return nil
}

func (dt DToken) String(i int) (string, error) {
	if (i < 0) || (i >= len(dt.Values)) {
		return "", fmt.Errorf("i=%d out of range (%d values)", i, len(dt.Values))
	}
	return string(dt.Values[i]), nil
}

func (dt DToken) check(i int) error {
	if i < 0 {
		return fmt.Errorf("negative i=%d", i)
	}
	if i > coding.MaxValues {
		return fmt.Errorf("cannot store more than %d values (i=%d)", coding.MaxValues, i)
	}
	return nil
}

func (dt *DToken) set(i int, b []byte) {
	if i == len(dt.Values) {
		dt.Values = append(dt.Values, b)
		return
	}

	if i >= cap(dt.Values) {
		values := make([][]byte, coding.MaxValues+1)
		copy(values, dt.Values)
		dt.Values = values
	}

	if i >= len(dt.Values) {
		dt.Values = dt.Values[:i+1]
	}

	dt.Values[i] = b
}

// --------------------------------------
// Manage token in request context.
var tokenKey struct{}

// PutInCtx stores the decoded token in the request context.
func (dt DToken) PutInCtx(r *http.Request) *http.Request {
	parent := r.Context()
	child := context.WithValue(parent, tokenKey, dt)
	return r.WithContext(child)
}

// FromCtx gets the decoded token from the request context.
func FromCtx(r *http.Request) (DToken, error) {
	dt, ok := r.Context().Value(tokenKey).(DToken)
	if !ok {
		return dt, fmt.Errorf("no token in context %s", r.URL.Path)
	}
	return dt, nil
}
