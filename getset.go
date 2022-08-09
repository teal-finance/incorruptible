// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

package incorruptible

import (
	"fmt"
	"strconv"
)

// Get / Set for multiple fields at the same timeout

func (tv *TValues) Get(keyValues ...KVal) ([]KVal, error) {
	var err error
	for i := range keyValues {
		keyValues[i], err = keyValues[i].Get(tv)
		if err != nil {
			return nil, fmt.Errorf("%w at arg=%d", err, i)
		}
	}
	return keyValues, nil
}

func (tv *TValues) Set(keyValues ...KVal) error {
	for i := range keyValues {
		if err := keyValues[i].Set(tv); err != nil {
			return fmt.Errorf("%w at arg=%d", err, i)
		}
	}
	return nil
}

// Get / Set for Uint64

func (tv TValues) Uint64(key int) (uint64, error) {
	if err := tv.checkRead(key); err != nil {
		return 0, err
	}
	return BytesToUint64(tv.Values[key])
}

func (tv *TValues) SetUint64(key int, val uint64) error {
	if err := checkWrite(key); err != nil {
		return err
	}
	b := Uint64ToBytes(val)
	tv.set(key, b)
	return nil
}

// Get / Set for Int64

func (tv TValues) Int64(key int) (int64, error) {
	v, err := tv.Uint64(key)
	return int64(v), err
}

func (tv *TValues) SetInt64(key int, val int64) error {
	return tv.SetUint64(key, uint64(val))
}

// Get / Set for Bool

func (tv TValues) Bool(key int) (bool, error) {
	if err := tv.checkRead(key); err != nil {
		return false, err
	}

	b := tv.Values[key]
	switch len(b) {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("got %d bytes but want only 0 or 1 byte for boolean encoding", len(b))
	}
}

func (tv *TValues) SetBool(key int, val bool) error {
	if err := checkWrite(key); err != nil {
		return err
	}

	var buf []byte // false --> length=0
	if val {
		buf = []byte{0} // true --> length=1
	}

	tv.set(key, buf)
	return nil
}

// Get / Set for String

func (tv TValues) String(key int) (string, error) {
	if err := tv.checkRead(key); err != nil {
		return "", err
	}
	return string(tv.Values[key]), nil
}

func (tv *TValues) SetString(key int, val string) error {
	if err := checkWrite(key); err != nil {
		return err
	}

	tv.set(key, []byte(val))
	return nil
}

// Get / Set with default value in lieu of returning an error

func (tv TValues) Uint64IfAny(key int, defaultValue ...uint64) uint64 {
	v, err := tv.Uint64(key)
	if err != nil {
		return defaultUint64(defaultValue...)
	}
	return v
}

func (tv TValues) Int64IfAny(key int, defaultValue ...int64) int64 {
	v, err := tv.Int64(key)
	if err != nil {
		return defaultInt64(defaultValue...)
	}
	return v
}

func (tv TValues) BoolIfAny(key int, defaultValue ...bool) bool {
	v, err := tv.Bool(key)
	if err != nil {
		return defaultBool(defaultValue...)
	}
	return v
}

func (tv TValues) StringIfAny(key int, defaultValue ...string) string {
	v, err := tv.String(key)
	if err != nil {
		return defaultString(defaultValue...)
	}
	return v
}

type (
	KUint64 struct {
		Key int
		Val uint64
	}
	KInt64 struct {
		Key int
		Val int64
	}
	KBool struct {
		Key int
		Val bool
	}
	KString struct {
		Key int
		Val string
	}
)

type KVal interface {
	Set(*TValues) error
	Get(*TValues) (KVal, error)
	Uint64() uint64
	Int64() int64
	Bool() bool
	String() string
}

func Uint64(k int, v ...uint64) KUint64 { return KUint64{k, defaultUint64(v...)} }
func Int64(k int, v ...int64) KInt64    { return KInt64{k, defaultInt64(v...)} }
func Bool(k int, v ...bool) KBool       { return KBool{k, defaultBool(v...)} }
func String(k int, v ...string) KString { return KString{k, defaultString(v...)} }

func (tv TValues) KUint64(k int, v ...uint64) KUint64 { return Uint64(k, v...) }
func (tv TValues) KInt64(k int, v ...int64) KInt64    { return Int64(k, v...) }
func (tv TValues) KBool(k int, v ...bool) KBool       { return Bool(k, v...) }
func (tv TValues) KString(k int, v ...string) KString { return String(k, v...) }

func (kv KUint64) Set(tv *TValues) error { return tv.SetUint64(kv.Key, kv.Val) }
func (kv KInt64) Set(tv *TValues) error  { return tv.SetInt64(kv.Key, kv.Val) }
func (kv KBool) Set(tv *TValues) error   { return tv.SetBool(kv.Key, kv.Val) }
func (kv KString) Set(tv *TValues) error { return tv.SetString(kv.Key, kv.Val) }

func (kv KUint64) Get(tv *TValues) (_ KVal, e error) { kv.Val, e = tv.Uint64(kv.Key); return kv, e }
func (kv KInt64) Get(tv *TValues) (_ KVal, e error)  { kv.Val, e = tv.Int64(kv.Key); return kv, e }
func (kv KBool) Get(tv *TValues) (_ KVal, e error)   { kv.Val, e = tv.Bool(kv.Key); return kv, e }
func (kv KString) Get(tv *TValues) (_ KVal, e error) { kv.Val, e = tv.String(kv.Key); return kv, e }

func (kv KUint64) Uint64() uint64 { return kv.Val }
func (kv KInt64) Uint64() uint64  { return uint64(kv.Val) }
func (kv KBool) Uint64() uint64   { return toUint64(kv.Val) }
func (kv KString) Uint64() uint64 { v, _ := strconv.Atoi(kv.Val); return uint64(v) }

func (kv KUint64) Int64() int64 { return int64(kv.Val) }
func (kv KInt64) Int64() int64  { return kv.Val }
func (kv KBool) Int64() int64   { return int64(toUint64(kv.Val)) }
func (kv KString) Int64() int64 { v, _ := strconv.Atoi(kv.Val); return int64(v) }

func (kv KUint64) Bool() bool { return kv.Val != 0 }
func (kv KInt64) Bool() bool  { return kv.Val != 0 }
func (kv KBool) Bool() bool   { return kv.Val }
func (kv KString) Bool() bool { return kv.Val != "" }

func (kv KUint64) String() string { return strconv.FormatUint(kv.Val, 10) }
func (kv KInt64) String() string  { return strconv.FormatInt(kv.Val, 10) }
func (kv KBool) String() string   { return "" }
func (kv KString) String() string { return kv.Val }

func toUint64(v bool) uint64 {
	if v {
		return 1
	}
	return 0
}

func defaultUint64(defaultValue ...uint64) uint64 {
	if len(defaultValue) == 0 {
		return 0
	}
	return defaultValue[0]
}

func defaultInt64(defaultValue ...int64) int64 {
	if len(defaultValue) == 0 {
		return 0
	}
	return defaultValue[0]
}

func defaultBool(defaultValue ...bool) bool {
	if len(defaultValue) == 0 {
		return false
	}
	return defaultValue[0]
}

func defaultString(defaultValue ...string) string {
	if len(defaultValue) == 0 {
		return ""
	}
	return defaultValue[0]
}

func checkWrite(key int) error {
	if key < 0 {
		return fmt.Errorf("key=%d must not be negative", key)
	}
	if key > MaxValues {
		return fmt.Errorf("key=%d is over max=%d storage", MaxValues, key)
	}
	return nil
}

func (tv TValues) checkRead(key int) error {
	if key < 0 {
		return fmt.Errorf("key=%d must not be negative", key)
	}
	if key >= len(tv.Values) {
		return fmt.Errorf("key=%d out of range: max=%d", key, len(tv.Values)-1)
	}
	return nil
}

func (tv *TValues) set(key int, buf []byte) {
	if key == len(tv.Values) {
		tv.Values = append(tv.Values, buf)
		return
	}

	if key >= cap(tv.Values) {
		values := make([][]byte, MaxValues+1)
		copy(values, tv.Values)
		tv.Values = values
	}

	if key >= len(tv.Values) {
		tv.Values = tv.Values[:key+1]
	}

	tv.Values[key] = buf
}
