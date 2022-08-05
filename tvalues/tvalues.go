// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

// Package tvalues (Token Values) represents the decoded form of a "session" token.
package tvalues

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

type TValues struct {
	Expires int64 // Unix time UTC (seconds since 1970)
	IP      net.IP
	Values  [][]byte
}

// New returns an empty TValues that can be used to generate a minimalist token.
func New() TValues {
	return TValues{Expires: 0, IP: nil, Values: nil}
}

func (tv *TValues) SetExpiry(maxAge int) {
	if maxAge > 0 {
		d := time.Duration(int64(maxAge) * 1_000_000_000)
		tv.SetExpiryDuration(d)
	}
}

func (tv *TValues) SetExpiryDuration(d time.Duration) {
	tv.SetExpiryTime(time.Now().Add(d))
}

func (tv *TValues) SetExpiryTime(t time.Time) {
	tv.Expires = t.Unix()
}

func (tv TValues) ExpiryTime() time.Time {
	if tv.Expires <= 0 {
		return time.Time{}
	}
	return time.Unix(tv.Expires, 0)
}

func (tv TValues) MaxAge() int {
	if tv.Expires <= 0 {
		return 0
	}
	return int(tv.Expires - time.Now().Unix())
}

func (tv *TValues) SetRemoteIP(r *http.Request) error {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return fmt.Errorf("setting IP but %w", err)
	}
	tv.IP = net.ParseIP(ip)
	tv.ShortenIP4Length()
	return nil
}

func (tv TValues) Valid(r *http.Request) error {
	if !tv.ValidExpiry() {
		return fmt.Errorf("expired or malformed or date in the far future: %ds %v",
			tv.Expires, time.Unix(tv.Expires, 0))
	}
	return tv.ValidIP(r)
}

func (tv TValues) ValidExpiry() bool {
	if tv.Expires == 0 {
		return true
	}
	c := tv.CompareExpiry()
	return (c == 0)
}

func (tv TValues) ValidIP(r *http.Request) error {
	if tv.NoIP() {
		return nil // anonymous token without IP
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return fmt.Errorf("checking token but %w", err)
	}
	if !tv.IP.Equal(net.ParseIP(ip)) {
		return fmt.Errorf("token says IP=%v but got %v", tv.IP, ip)
	}

	return nil
}

// NoIP returns true when no IP is set within the TValues.
// NoIP returns false when an IP is present.
func (tv TValues) NoIP() bool {
	return len(tv.IP) == 0
}

func (tv *TValues) EmptyIP() {
	tv.IP = nil
}

func (tv *TValues) ShortenIP4Length() {
	if tv.IP == nil {
		return
	}
	if v4 := tv.IP.To4(); v4 != nil {
		tv.IP = v4
	}
}

func (tv TValues) CompareExpiry() int {
	now := time.Now().Unix()
	if tv.Expires < now {
		return -1
	}
	if tv.Expires > now+secondsPerYear {
		return 1
	}
	return 0
}

func (tv *TValues) SetUint64(i int, v uint64) error {
	if err := tv.check(i); err != nil {
		return err
	}
	b := coding.Uint64ToBytes(v)
	tv.set(i, b)
	return nil
}

func (tv TValues) Uint64(i int) (uint64, error) {
	if (i < 0) || (i >= len(tv.Values)) {
		return 0, fmt.Errorf("i=%d out of range (%d values)", i, len(tv.Values))
	}
	return coding.BytesToUint64(tv.Values[i])
}

func (tv *TValues) SetBool(i int, value bool) error {
	if err := tv.check(i); err != nil {
		return err
	}

	var buf []byte // false --> length=0
	if value {
		buf = []byte{0} // true --> length=1
	}

	tv.set(i, buf)
	return nil
}

func (tv TValues) Bool(i int) (bool, error) {
	if (i < 0) || (i >= len(tv.Values)) {
		return false, fmt.Errorf("i=%d out of range (%d values)", i, len(tv.Values))
	}

	b := tv.Values[i]

	switch len(b) {
	default:
		return false, fmt.Errorf("too much bytes (length=%d) for a boolean", len(b))
	case 1:
		return true, nil
	case 0:
		return false, nil
	}
}

func (tv *TValues) SetString(i int, s string) error {
	if err := tv.check(i); err != nil {
		return err
	}

	tv.set(i, []byte(s))
	return nil
}

func (tv TValues) String(i int) (string, error) {
	if (i < 0) || (i >= len(tv.Values)) {
		return "", fmt.Errorf("i=%d out of range (%d values)", i, len(tv.Values))
	}
	return string(tv.Values[i]), nil
}

func (tv TValues) Uint64IfAny(i int, defaultValue ...uint64) uint64 {
	v, err := tv.Uint64(i)
	if err != nil {
		if len(defaultValue) == 0 {
			return 0
		}
		return defaultValue[0]
	}
	return v
}

func (tv TValues) BoolIfAny(i int, defaultValue ...bool) bool {
	v, err := tv.Bool(i)
	if err != nil {
		if len(defaultValue) == 0 {
			return false
		}
		return defaultValue[0]
	}
	return v
}

func (tv TValues) StringIfAny(i int, defaultValue ...string) string {
	v, err := tv.String(i)
	if err != nil {
		if len(defaultValue) == 0 {
			return ""
		}
		return defaultValue[0]
	}
	return v
}

func (tv TValues) check(i int) error {
	if i < 0 {
		return fmt.Errorf("negative i=%d", i)
	}
	if i > coding.MaxValues {
		return fmt.Errorf("cannot store more than %d values (i=%d)", coding.MaxValues, i)
	}
	return nil
}

func (tv *TValues) set(i int, buf []byte) {
	if i == len(tv.Values) {
		tv.Values = append(tv.Values, buf)
		return
	}

	if i >= cap(tv.Values) {
		values := make([][]byte, coding.MaxValues+1)
		copy(values, tv.Values)
		tv.Values = values
	}

	if i >= len(tv.Values) {
		tv.Values = tv.Values[:i+1]
	}

	tv.Values[i] = buf
}

// --------------------------------------
// Set/Get token to/from request context.
//
//nolint:gochecknoglobals // Context access key need to be global variable.
var key struct{}

// ToCtx stores the decoded token in the request context.
func (tv TValues) ToCtx(r *http.Request) *http.Request {
	parent := r.Context()
	child := context.WithValue(parent, key, tv)
	return r.WithContext(child)
}

// FromCtx gets the decoded token from the request context.
func FromCtx(r *http.Request) (TValues, bool) {
	tv, ok := r.Context().Value(key).(TValues)
	return tv, ok
}
