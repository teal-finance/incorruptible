// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

package incorruptible

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

const (
	secondsPerMinute = 60
	secondsPerHour   = 60 * secondsPerMinute
	secondsPerDay    = 24 * secondsPerHour      // = 86400
	secondsPerYear   = 365.2425 * secondsPerDay // = 31556952 = average including leap years
)

// TValues (Token Values) represents the decoded form of an Incorruptible token.
type TValues struct {
	Expires int64  // Unix time UTC (seconds since 1970)
	IP      net.IP // TOTO: use netip.Addr
	Values  [][]byte
}

// EmptyTValues returns an empty TValues that can be used to generate a minimalist token.
func EmptyTValues() TValues {
	return TValues{Expires: 0, IP: nil, Values: nil}
}

// NewTValues returns an empty TValues that can be used to generate a minimalist token.
func NewTValues(keyValues ...KVal) (TValues, error) {
	tv := EmptyTValues()
	err := tv.Set(keyValues...)
	return tv, err
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

// --------------------------------------
// Set/Get token to/from request context.
//
//nolint:gochecknoglobals // Context access key need to be global variable.
var contextKey struct{}

// ToCtx stores the decoded token in the request context.
func (tv TValues) ToCtx(r *http.Request) *http.Request {
	parent := r.Context()
	child := context.WithValue(parent, contextKey, tv)
	return r.WithContext(child)
}

// FromCtx gets the decoded token from the request context.
func FromCtx(r *http.Request) (TValues, bool) {
	tv, ok := r.Context().Value(contextKey).(TValues)
	return tv, ok
}
