// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

package format_test

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/teal-finance/incorruptible/format"
	"github.com/teal-finance/incorruptible/format/coding"
	"github.com/teal-finance/incorruptible/tvalues"
)

var expiry = time.Date(coding.ExpiryStartYear, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

var cases = []struct {
	name    string
	magic   uint8
	wantErr bool
	tvalues tvalues.TValues
}{
	{
		"noIP", 109, false, tvalues.TValues{
			Expires: expiry,
			IP:      nil,
			Values:  nil,
		},
	},
	{
		"noIPnoExpiry", 109, false, tvalues.TValues{
			Expires: 0,
			IP:      nil,
			Values:  nil,
		},
	},
	{
		"noExpiry", 109, false, tvalues.TValues{
			Expires: 0,
			IP:      net.IPv4(0, 0, 0, 0),
			Values:  nil,
		},
	},
	{
		"noneIPv4", 0x51, false,
		tvalues.TValues{
			Expires: expiry,
			IP:      net.IPv4(11, 22, 33, 44),
			Values:  [][]byte{},
		},
	},
	{
		"noneIPv6", 0x51, false,
		tvalues.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  [][]byte{},
		},
	},
	{
		"1emptyIPv6", 0x51, false,
		tvalues.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  [][]byte{[]byte("")},
		},
	},
	{
		"4emptyIPv6", 0x51, false,
		tvalues.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  [][]byte{[]byte(""), []byte(""), []byte(""), []byte("")},
		},
	},
	{
		"1smallIPv6", 0x51, false,
		tvalues.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  [][]byte{[]byte("1")},
		},
	},
	{
		"1valIPv6", 0x51, false,
		tvalues.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  [][]byte{[]byte("123456789-B-123456789-C-123456789-D-123456789-E-123456789")},
		},
	},
	{
		"1moreIPv6", 0x51, false,
		tvalues.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  [][]byte{[]byte("123456789-B-123456789-C-123456789-D-123456789-E-123456789-")},
		},
	},
	{
		"Compress 10valIPv6", 0x51, false,
		tvalues.TValues{
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
		"too much values", 0x51, true,
		tvalues.TValues{
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

func TestUnmarshal(t *testing.T) {
	t.Parallel()

	for _, c := range cases {
		c := c

		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			c.tvalues.ShortenIP4Length()

			b, err := format.Marshal(c.tvalues, c.magic)
			if (err == nil) == c.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, c.wantErr)
				return
			}

			t.Log("len(b)", len(b))

			n := len(b)
			if n == 0 {
				return
			}
			if n > 70 {
				n = 70 // print max the first 70 bytes
			}
			t.Logf("b[:%d] %v", n, b[:n])

			magic := coding.MagicCode(b)
			if magic != c.magic {
				t.Errorf("MagicCode() got = %x, want = %x", magic, c.magic)
				return
			}

			if format.EnablePadding && ((len(b) % 4) != 0) {
				t.Errorf("len(b) %d must be 32-bit aligned but gap =%d", len(b), len(b)%4)
				return
			}

			got, err := format.Unmarshal(b)
			if err != nil {
				t.Errorf("Unmarshal() error = %v", err)
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
		})
	}
}
