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
)

func TestDecode(t *testing.T) {
	t.Parallel()

	for _, c := range encoderDataCases {
		c := c

		u, err := url.Parse("http://host:8080/path/url")
		if err != nil {
			t.Error("url.Parse() error", err)
			return
		}

		aesKey := "1234567890" + "123456"                           // 16 bytes = AES 128-bit key
		chaKey := "1234567890" + "1234567890" + "1234567890" + "12" // 32 bytes = 256-bit ChaCha20-Poly1305 key
		for _, key := range []string{aesKey, chaKey} {
			secretKey := []byte(key)

			incorr := incorruptible.New(nil, []*url.URL{u}, secretKey, "session", 0, true)

			t.Run(c.name, func(t *testing.T) {
				t.Parallel()

				c.tv.ShortenIP4Length()

				token, err := incorr.Encode(c.tv)
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
					t.Error("Decode() error =", err)
					return
				}

				min := c.tv.Expires - incorruptible.PrecisionInSeconds
				max := c.tv.Expires + incorruptible.PrecisionInSeconds
				validExpiry := (min <= got.Expires) && (got.Expires <= max)
				if !validExpiry {
					t.Errorf("Expiry too different got=%v original=%v want in [%d %d]",
						got.Expires, c.tv.Expires, min, max)
				}

				if (len(got.IP) > 0 || len(c.tv.IP) > 0) &&
					!reflect.DeepEqual(got.IP, c.tv.IP) {
					t.Errorf("Mismatch IP got %v, want %v", got.IP, c.tv.IP)
				}

				if (len(got.Values) > 0 || len(c.tv.Values) > 0) &&
					!reflect.DeepEqual(got.Values, c.tv.Values) {
					t.Errorf("Mismatch Values got %v, want %v", got.Values, c.tv.Values)
				}

				cookie, err := incorr.NewCookieFromValues(c.tv)
				if err != nil {
					t.Error("NewCookie()", err)
					return
				}

				err = cookie.Valid()
				if err != nil {
					if cookie.Expires.IsZero() {
						// https://github.com/golang/go/issues/52989
						if err.Error() == "http: invalid Cookie.Expires" {
							return
						}
						t.Fatal("The workaround about 'invalid Cookie.Expires' must be reviewed:", err)
					}
					t.Error("Invalid cookie:", err)
				}
			})
		}
	}
}

var expiry = time.Date(incorruptible.ExpiryStartYear, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

var encoderDataCases = []struct {
	name    string
	wantErr bool
	tv      incorruptible.TValues
}{
	{
		"noIP", false, incorruptible.TValues{
			Expires: expiry,
			IP:      nil,
			Values:  nil,
		},
	},
	{
		"noIPnoExpiry", false, incorruptible.TValues{
			Expires: 0,
			IP:      nil,
			Values:  nil,
		},
	},
	{
		"noExpiry", false, incorruptible.TValues{
			Expires: 0,
			IP:      net.IPv4(0, 0, 0, 0),
			Values:  nil,
		},
	},
	{
		"noneIPv4", false, incorruptible.TValues{
			Expires: expiry,
			IP:      net.IPv4(11, 22, 33, 44),
			Values:  nil,
		},
	},
	{
		"noneIPv6", false, incorruptible.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  [][]byte{},
		},
	},
	{
		"1emptyIPv6", false, incorruptible.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  [][]byte{[]byte("")},
		},
	},
	{
		"4emptyIPv6", false, incorruptible.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  [][]byte{[]byte(""), []byte(""), []byte(""), []byte("")},
		},
	},
	{
		"1smallIPv6", false, incorruptible.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  [][]byte{[]byte("1")},
		},
	},
	{
		"1valIPv6", false, incorruptible.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  [][]byte{[]byte("123456789-B-123456789-C-123456789-D-123456789-E-123456789")},
		},
	},
	{
		"1moreIPv6", false, incorruptible.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  [][]byte{[]byte("123456789-B-123456789-C-123456789-D-123456789-E-123456789-")},
		},
	},
	{
		"Compress 10valIPv6", false, incorruptible.TValues{
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
		"too much values", true, incorruptible.TValues{
			Expires: expiry,
			IP:      net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Values:  values,
		},
	},
}

var values = [][]byte{
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
}
