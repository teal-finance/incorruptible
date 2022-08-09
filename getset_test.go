// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

package incorruptible_test

import (
	"math"
	"strconv"
	"testing"

	"github.com/teal-finance/incorruptible"
)

func TestTValues_Uint64(t *testing.T) {
	t.Parallel()

	for _, c := range dataCases {
		// duplicate case data to enable parallel testing
		c := c
		c.tv.Values = append([][]byte(nil), c.tv.Values...)

		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			if err := c.tv.SetUint64(c.key, c.val); (err != nil) != c.wantErr {
				t.Errorf("SetUint64() error = %v, wantErr %v", err, c.wantErr)
			}

			v, err := c.tv.Uint64(c.key)
			if (err != nil) != c.wantErr {
				t.Errorf("Uint64() error = %v, wantErr %v", err, c.wantErr)
			}
			if !c.wantErr && (v != c.val) {
				t.Errorf("Uint64() Mismatch got %v, want %v", v, c.val)
			}

			v = c.tv.Uint64IfAny(c.key, 12345)
			if (v == 12345) != c.wantErr {
				t.Errorf("Uint64IfAny() got=%v, wantErr %v", v, c.wantErr)
			}
			if !c.wantErr && (v != c.val) {
				t.Errorf("Uint64IfAny() Mismatch got %v, want %v", v, c.val)
			}
		})
	}
}

func TestTValues_Int64(t *testing.T) {
	t.Parallel()

	for _, c := range dataCases {
		// duplicate case data to enable parallel testing
		c := c
		c.tv.Values = append([][]byte(nil), c.tv.Values...)

		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			v1 := int64(c.val)
			if err := c.tv.SetInt64(c.key, v1); (err != nil) != c.wantErr {
				t.Errorf("SetUint64() error = %v, wantErr %v", err, c.wantErr)
			}

			v2, err := c.tv.Int64(c.key)
			if (err != nil) != c.wantErr {
				t.Errorf("Uint64() error = %v, wantErr %v", err, c.wantErr)
			}
			if !c.wantErr && (v2 != v1) {
				t.Errorf("Uint64() Mismatch got %v, want %v", v2, v1)
			}

			v2 = c.tv.Int64IfAny(c.key, 12345)
			if (v2 == 12345) != c.wantErr {
				t.Errorf("Uint64IfAny() got=%v, wantErr %v", v2, c.wantErr)
			}
			if !c.wantErr && (v2 != v1) {
				t.Errorf("Uint64IfAny() Mismatch got %v, want %v", v2, v1)
			}
		})
	}
}

func TestTValues_Bool(t *testing.T) {
	t.Parallel()

	for _, c := range dataCases {
		// duplicate case data to enable parallel testing
		c := c
		c.tv.Values = append([][]byte(nil), c.tv.Values...)

		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			v1 := ((c.val % 2) == 0)

			if err := c.tv.SetBool(c.key, v1); (err != nil) != c.wantErr {
				t.Errorf("SetBool() error = %v, wantErr %v", err, c.wantErr)
			}

			v2, err := c.tv.Bool(c.key)
			if (err != nil) != c.wantErr {
				t.Errorf("Bool() error = %v, wantErr %v", err, c.wantErr)
			}

			if c.wantErr {
				return
			}

			if v2 != v1 {
				t.Errorf("Bool() mismatch got %v, want %v", v2, v1)
			}

			v2 = c.tv.BoolIfAny(c.key, true)
			if v2 != v1 {
				t.Errorf("BoolIfAny() mismatch got %v, want %v", v2, v1)
			}
		})
	}
}

func TestTValues_String(t *testing.T) {
	t.Parallel()

	for _, c := range dataCases {
		// duplicate case data to enable parallel testing
		c := c
		c.tv.Values = append([][]byte(nil), c.tv.Values...)

		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			v1 := ""
			if c.val > 3 {
				v1 = c.name + strconv.FormatUint(c.val, 2)
			}

			if err := c.tv.SetString(c.key, v1); (err != nil) != c.wantErr {
				t.Fatalf("SetString() error = %v, wantErr %v", err, c.wantErr)
			}

			v2, err := c.tv.String(c.key)
			if (err != nil) != c.wantErr {
				t.Errorf("String() error = %v, wantErr %v", err, c.wantErr)
			}
			if !c.wantErr && (v2 != v1) {
				t.Errorf("Mismatch got %v, want %v", v2, v1)
			}

			v2 = c.tv.StringIfAny(c.key, "Foo")
			if (v2 == "Foo") != c.wantErr {
				t.Errorf("StringIfAny() got=%v, wantErr %v", v2, c.wantErr)
			}
			if !c.wantErr && (v2 != v1) {
				t.Errorf("StringIfAny() Mismatch got %v, want %v", v2, v1)
			}
		})
	}
}

func TestTValues_Set(t *testing.T) {
	t.Parallel()

	for _, c := range dataCases {
		// duplicate case data to enable parallel testing
		c := c
		c.tv.Values = append([][]byte(nil), c.tv.Values...)

		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			b := c.tv.KBool(keyB, c.val == 0)
			i := c.tv.KInt64(keyI, int64(c.val))
			u := c.tv.KUint64(c.key, c.val)
			s := c.tv.KString(keyS, strconv.Itoa(int(c.val)))

			if err := c.tv.Set(i, u, b, s); (err != nil) != c.wantErr {
				t.Errorf("TValues.Set() error = %v, wantErr %v", err, c.wantErr)
			}

			kb := c.tv.KBool(keyB)
			ki := c.tv.KInt64(keyI)
			ku := c.tv.KUint64(c.key)
			ks := c.tv.KString(keyS)

			values, err := c.tv.Get(kb, ks, ki, ku)
			if (err != nil) != c.wantErr {
				t.Errorf("Set() error = %v, wantErr %v", err, c.wantErr)
			}
			if !c.wantErr {
				if len(values) != 4 {
					t.Errorf("Get() want len=4 got=%d", len(values))
				}
				if values[0].Bool() != b.Val {
					t.Errorf("Get() Bool() want=%v got=%v", b.Val, values[0].Bool())
				}
				if values[1].String() != s.Val {
					t.Errorf("Get() String() want=%v got=%v", s.Val, values[1].String())
				}
				if values[2].Int64() != i.Val {
					t.Errorf("Get() String() want=%v got=%v", i.Val, values[2].String())
				}
				if values[3].Uint64() != u.Val {
					t.Errorf("Get() Uint64() want=%v got=%v", u.Val, values[3].String())
				}
			}
			v, err := c.tv.Uint64(c.key)
			if (err != nil) != c.wantErr {
				t.Errorf("Uint64() error = %v, wantErr %v", err, c.wantErr)
			}
			if !c.wantErr && (v != c.val) {
				t.Errorf("Uint64() mismatch got %v, want %v", v, c.val)
			}

			ii, err := c.tv.Int64(keyI)
			if err != nil {
				t.Errorf("Int64() error = %v,", err)
			}
			if ii != i.Val {
				t.Errorf("Int64() mismatch got %v, want %v", ii, i.Val)
			}

			if c.wantErr {
				return
			}

			bb, err := c.tv.Bool(keyB)
			if err != nil {
				t.Errorf("Bool() error = %v,", err)
			}
			if bb != b.Val {
				t.Errorf("Bool() mismatch got %v, want %v", ii, i.Val)
			}

			ss, err := c.tv.String(keyS)
			if err != nil {
				t.Errorf("String() error = %v,", err)
			}
			if ss != s.Val {
				t.Errorf("String() mismatch got %v, want %v", ii, i.Val)
			}
		})
	}
}

const (
	keyI = 2
	keyB = 3
	keyS = 4
)

var dataCases = []struct {
	name    string
	key     int
	val     uint64
	wantErr bool
	tv      incorruptible.TValues
}{
	{"v=0", 0, 0, false, incorruptible.TValues{}},
	{"v=1", 0, 1, false, incorruptible.TValues{}},
	{"v=255", 0, 255, false, incorruptible.TValues{}},
	{"v=256", 0, 256, false, incorruptible.TValues{}},
	{"v=65000", 0, 65000, false, incorruptible.TValues{}},
	{"v=66000", 0, 66000, false, incorruptible.TValues{}},
	{"v=2²⁴", 0, 1 << 24, false, incorruptible.TValues{}},
	{"v=2³³", 0, 1 << 33, false, incorruptible.TValues{}},
	{"v=MAX", 0, math.MaxUint64, false, incorruptible.TValues{}},

	{"i=1", 1, 0, false, incorruptible.TValues{}},
	{"i=2", 5, 4, false, incorruptible.TValues{}},
	{"i=9", 9, 999, false, incorruptible.TValues{}},
	{"i=31", incorruptible.MaxValues, 9999, false, incorruptible.TValues{}},
	{"i=32", incorruptible.MaxValues + 1, 9, true, incorruptible.TValues{}},
	{"i=-1", -1, 9, true, incorruptible.TValues{}},

	{"i=0 len=5", 0, 0, false, incorruptible.TValues{Values: make([][]byte, 5)}},
	{"i=1 len=5", 1, 999, false, incorruptible.TValues{Values: make([][]byte, 5)}},
	{"i=4 len=5", 5, 99999, false, incorruptible.TValues{Values: make([][]byte, 5)}},
	{"i=5 len=5", 6, 99999999, false, incorruptible.TValues{Values: make([][]byte, 5)}},
	{"i=6 len=5", 7, 999999999999, false, incorruptible.TValues{Values: make([][]byte, 5)}},
	{"i=9 len=5", 9, 999999999999999, false, incorruptible.TValues{Values: make([][]byte, 5)}},
	{"i=31 len=5", incorruptible.MaxValues, 9, false, incorruptible.TValues{Values: make([][]byte, 5)}},
	{"i=32 len=5", incorruptible.MaxValues + 1, 9, true, incorruptible.TValues{Values: make([][]byte, 5)}},

	{"i=0 cap=5", 0, 9, false, incorruptible.TValues{Values: make([][]byte, 0, 5)}},
	{"i=1 cap=5", 1, 999, false, incorruptible.TValues{Values: make([][]byte, 0, 5)}},
	{"i=4 len=5", 5, 99999, false, incorruptible.TValues{Values: make([][]byte, 0, 5)}},
	{"i=5 len=5", 6, 99999999, false, incorruptible.TValues{Values: make([][]byte, 0, 5)}},
	{"i=6 len=5", 7, 99999999999, false, incorruptible.TValues{Values: make([][]byte, 0, 5)}},
	{"i=9 cap=5", 9, math.MaxUint64, false, incorruptible.TValues{Values: make([][]byte, 0, 5)}},
	{"i=31 cap=5", incorruptible.MaxValues, 9, false, incorruptible.TValues{Values: make([][]byte, 0, 5)}},
	{"i=32 cap=5", incorruptible.MaxValues + 1, 9, true, incorruptible.TValues{Values: make([][]byte, 0, 5)}},
}
