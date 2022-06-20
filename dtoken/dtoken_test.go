// Copyright (c) 2022 Teal.Finance contributors
// This file is part of Teal.Finance/incorruptible licensed under the MIT License.
// SPDX-License-Identifier: MIT

package dtoken_test

import (
	"math"
	"strconv"
	"testing"

	"github.com/teal-finance/incorruptible/dtoken"
)

var cases = []struct {
	name    string
	i       int
	v       uint64
	wantErr bool
	t       dtoken.DToken
}{
	{"v=0", 0, 0, false, dtoken.DToken{}},
	{"v=1", 0, 1, false, dtoken.DToken{}},
	{"v=255", 0, 255, false, dtoken.DToken{}},
	{"v=256", 0, 256, false, dtoken.DToken{}},
	{"v=65000", 0, 65000, false, dtoken.DToken{}},
	{"v=66000", 0, 66000, false, dtoken.DToken{}},
	{"v=2²⁴", 0, 1 << 24, false, dtoken.DToken{}},
	{"v=2³³", 0, 1 << 33, false, dtoken.DToken{}},
	{"v=MAX", 0, math.MaxUint64, false, dtoken.DToken{}},

	{"i=1", 1, 9, false, dtoken.DToken{}},
	{"i=2", 2, 9, false, dtoken.DToken{}},
	{"i=9", 9, 9, false, dtoken.DToken{}},
	{"i=31", 31, 9, false, dtoken.DToken{}},
	{"i=32", 32, 9, true, dtoken.DToken{}},

	{"i=1 len=5", 1, 9, false, dtoken.DToken{Values: make([][]byte, 5)}},
	{"i=1 len=5", 1, 9, false, dtoken.DToken{Values: make([][]byte, 5)}},
	{"i=4 len=5", 4, 9, false, dtoken.DToken{Values: make([][]byte, 5)}},
	{"i=5 len=5", 5, 9, false, dtoken.DToken{Values: make([][]byte, 5)}},
	{"i=6 len=5", 6, 9, false, dtoken.DToken{Values: make([][]byte, 5)}},
	{"i=9 len=5", 9, 9, false, dtoken.DToken{Values: make([][]byte, 5)}},
	{"i=31 len=5", 31, 9, false, dtoken.DToken{Values: make([][]byte, 5)}},
	{"i=32 len=5", 32, 9, true, dtoken.DToken{Values: make([][]byte, 5)}},

	{"i=1 cap=5", 1, 9, false, dtoken.DToken{Values: make([][]byte, 0, 5)}},
	{"i=1 cap=5", 1, 9, false, dtoken.DToken{Values: make([][]byte, 0, 5)}},
	{"i=4 len=5", 4, 9, false, dtoken.DToken{Values: make([][]byte, 0, 5)}},
	{"i=5 len=5", 5, 9, false, dtoken.DToken{Values: make([][]byte, 0, 5)}},
	{"i=6 len=5", 6, 9, false, dtoken.DToken{Values: make([][]byte, 0, 5)}},
	{"i=9 cap=5", 9, 9, false, dtoken.DToken{Values: make([][]byte, 0, 5)}},
	{"i=31 cap=5", 31, 9, false, dtoken.DToken{Values: make([][]byte, 0, 5)}},
	{"i=32 cap=5", 32, 9, true, dtoken.DToken{Values: make([][]byte, 0, 5)}},
}

func TestToken_Uint64(t *testing.T) {
	t.Parallel()

	for _, c := range cases {
		c := c

		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			if err := c.t.SetUint64(c.i, c.v); (err != nil) != c.wantErr {
				t.Errorf("DToken.SetUint64() error = %v, wantErr %v", err, c.wantErr)
			}

			v, err := c.t.Uint64(c.i)
			if (err != nil) != c.wantErr {
				t.Errorf("DToken.Uint64() error = %v, wantErr %v", err, c.wantErr)
			}

			if !c.wantErr && (v != c.v) {
				t.Errorf("Mismatch integer got %v, want %v", v, c.v)
			}
		})
	}
}

func TestToken_Bool(t *testing.T) {
	t.Parallel()

	for _, c := range cases {
		c := c

		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			v1 := ((c.v % 2) == 0)

			if err := c.t.SetBool(c.i, v1); (err != nil) != c.wantErr {
				t.Errorf("DToken.SetUint64() error = %v, wantErr %v", err, c.wantErr)
			}

			v2, err := c.t.Bool(c.i)
			if (err != nil) != c.wantErr {
				t.Errorf("DToken.Uint64() error = %v, wantErr %v", err, c.wantErr)
			}

			if !c.wantErr && (v2 != v1) {
				t.Errorf("Mismatch integer got %v, want %v", v2, v1)
			}
		})
	}
}

func TestToken_String(t *testing.T) {
	t.Parallel()

	for _, c := range cases {
		c := c

		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			v1 := ""
			if c.v > 3 {
				v1 += strconv.FormatUint(c.v, 10) + c.name
			}

			if err := c.t.SetString(c.i, v1); (err != nil) != c.wantErr {
				t.Errorf("DToken.SetUint64() error = %v, wantErr %v", err, c.wantErr)
			}

			v2, err := c.t.String(c.i)
			if (err != nil) != c.wantErr {
				t.Errorf("DToken.Uint64() error = %v, wantErr %v", err, c.wantErr)
			}

			if !c.wantErr && (v2 != v1) {
				t.Errorf("Mismatch integer got %v, want %v", v2, v1)
			}
		})
	}
}
