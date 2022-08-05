// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

package incorruptible_test

import (
	"net"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/teal-finance/incorruptible"
	"github.com/teal-finance/incorruptible/format/coding"
	"github.com/teal-finance/incorruptible/tvalues"
)

var expiry = time.Date(coding.ExpiryStartYear, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

var cases = []struct {
	name    string
	wantErr bool
	tvalues tvalues.TValues
}{
	{
		"noIP", false, tvalues.TValues{
			Expires: expiry,
			IP:      nil,
			Values:  nil,
		},
	},
	{
		"noIPnoExpiry", false, tvalues.TValues{
			Expires: 0,
			IP:      nil,
			Values:  nil,
		},
	},
	{
		"noExpiry", false, tvalues.TValues{
			Expires: 0,
			IP:      net.IPv4(0, 0, 0, 0),
			Values:  nil,
		},
	},
	{
		"noneIPv4", false, tvalues.TValues{
			Expires: expiry,
			IP:      net.IPv4(11, 22, 33, 44),
			Values:  nil,
		},
	},
	{
		"noneIPv6", false, tvalues.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  [][]byte{},
		},
	},
	{
		"1emptyIPv6", false, tvalues.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  [][]byte{[]byte("")},
		},
	},
	{
		"4emptyIPv6", false, tvalues.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  [][]byte{[]byte(""), []byte(""), []byte(""), []byte("")},
		},
	},
	{
		"1smallIPv6", false, tvalues.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  [][]byte{[]byte("1")},
		},
	},
	{
		"1valIPv6", false, tvalues.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  [][]byte{[]byte("123456789-B-123456789-C-123456789-D-123456789-E-123456789")},
		},
	},
	{
		"1moreIPv6", false, tvalues.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  [][]byte{[]byte("123456789-B-123456789-C-123456789-D-123456789-E-123456789-")},
		},
	},
	{
		"Compress 10valIPv6", false, tvalues.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values: [][]byte{
				[]byte("123456789-B-123456789-C-123456789-D-123456789-E-123456789"),
				[]byte("123456789-F-123456789-C-123456789-D-123456789-E-123456789"),
				[]byte("123456789-G-123456789-C-123456789-D-123456789-E-123456789"),
				[]byte("123456789-H-123456789-C-123456789-D-123456789-E-123456789"),
				[]byte("123456789-I-123456789-C-123456789-D-123456789-E-123456789"),
				[]byte("123456789-J-123456789-C-123456789-D-123456789-E-123456789"),
				[]byte("123456789-K-123456789-C-123456789-D-123456789-E-123456789"),
			},
		},
	},
	{
		"too much values", true, tvalues.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values: [][]byte{
				{1},
				{2},
				{3},
				{4},
				{5},
				{6},
				{7},
				{8},
				{9},
				{10},
				{11},
				{12},
				{13},
				{14},
				{15},
				{16},
				{17},
				{18},
				{19},
				{20},
				{21},
				{22},
				{23},
				{24},
				{25},
				{26},
				{27},
				{28},
				{29},
				{30},
				{31},
				{32},
				{33},
				{34},
				{35},
				{36},
				{37},
				{38},
				{39},
				{40},
				{41},
				{42},
				{43},
				{44},
				{45},
				{46},
				{47},
				{48},
				{49},
				{50},
				{51},
				{52},
				{53},
				{54},
				{55},
				{56},
				{57},
				{58},
				{59},
				{60},
				{61},
				{62},
				{63},
				{64},
				{65},
				{66},
				{67},
				{68},
				{69},
			},
		},
	},
}

func TestDecode(t *testing.T) {
	t.Parallel()

	for _, c := range cases {
		c := c

		u, err := url.Parse("http://host:8080/path/url")
		if err != nil {
			t.Error("url.Parse() error", err)
			return
		}

		key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6}

		incorr := incorruptible.New("session", []*url.URL{u}, key[:], 0, true, nil)

		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			c.tvalues.ShortenIP4Length()

			token, err := incorr.Encode(c.tvalues)
			if (err == nil) && c.wantErr {
				t.Errorf("Encode() no error but want an error")
				return
			}
			if (err != nil) && !c.wantErr {
				t.Errorf("Encode() err=%v, want no error", err)
				return
			}
			if err != nil {
				t.Log("Encode() OK err=", err)
				return
			}

			n := len(token)
			t.Log("len(token) =", n)
			if n < incorruptible.Base91MinSize {
				t.Error("len(token) < Base91MinSize =", incorruptible.Base91MinSize)
				return
			}
			if n > 70 {
				n = 70 // print max the first 70 characters
			}
			t.Logf("str len=%d [:%d]=%q", len(token), n, token[:n])

			got, err := incorr.Decode(token)
			if err != nil {
				t.Errorf("Decode() error = %v", err)
				return
			}

			min := c.tvalues.Expires - coding.PrecisionInSeconds
			max := c.tvalues.Expires + coding.PrecisionInSeconds
			validExpiry := (min <= got.Expires) && (got.Expires <= max)
			if !validExpiry {
				t.Errorf("Expiry too different got=%v original=%v want in [%d %d]",
					got.Expires, c.tvalues.Expires, min, max)
			}

			if (len(got.IP) > 0 || len(c.tvalues.IP) > 0) &&
				!reflect.DeepEqual(got.IP, c.tvalues.IP) {
				t.Errorf("Mismatch IP got %v, want %v", got.IP, c.tvalues.IP)
			}

			if (len(got.Values) > 0 || len(c.tvalues.Values) > 0) &&
				!reflect.DeepEqual(got.Values, c.tvalues.Values) {
				t.Errorf("Mismatch Values got %v, want %v", got.Values, c.tvalues.Values)
			}

			cookie, err := incorr.NewCookieFromDT(c.tvalues)
			if err != nil {
				t.Errorf("NewCookie() %v", err)
				return
			}

			err = cookie.Valid()
			// https://github.com/golang/go/issues/52989
			if err != nil && err.Error() != "http: invalid Cookie.Expires" {
				t.Errorf("Invalid cookie: %v", err)
				return
			}
		})
	}
}
