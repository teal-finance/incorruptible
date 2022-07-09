// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

package incorruptible

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

type WriteHTTP func(w http.ResponseWriter, r *http.Request, statusCode int, messages ...any)

// Write is a fast and pretty JSON marshaler.
func defaultWriteHTTP(w http.ResponseWriter, r *http.Request, statusCode int, messages ...any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)

	buf := make([]byte, 0, 1024)
	buf = append(buf, '{')

	if len(messages) > 0 {
		buf = appendMessages(buf, messages)
	}

	if r != nil {
		if len(messages) > 0 {
			buf = append(buf, ',', '\n')
		}
		buf = appendURL(buf, r.URL)
	}

	buf = append(buf, '}')
	_, _ = w.Write(buf)
}

func appendMessages(buf []byte, messages []any) []byte {
	buf = append(buf, []byte(`"error":`)...)
	buf = appendKey(buf, messages[0])

	for i := 1; i < len(messages); i += 2 {
		buf = append(buf, ',', '\n')
		buf = appendKey(buf, messages[i])
		buf = append(buf, ':')
		if i+1 < len(messages) {
			buf = appendValue(buf, messages[i+1])
		} else {
			buf = append(buf, '0')
		}
	}

	return buf
}

func appendURL(buf []byte, u *url.URL) []byte {
	buf = append(buf, []byte(`"path":`)...)
	buf = strconv.AppendQuote(buf, u.Path)
	if u.RawQuery != "" {
		buf = append(buf, []byte(",\n"+`"query":`)...)
		buf = strconv.AppendQuote(buf, u.RawQuery)
	}
	return buf
}

func appendKey(buf []byte, a any) []byte {
	switch val := a.(type) {
	case string:
		return strconv.AppendQuote(buf, val)
	case []byte:
		return strconv.AppendQuote(buf, string(val))
	default:
		return strconv.AppendQuote(buf, fmt.Sprint(val))
	}
}

func appendValue(buf []byte, a any) []byte {
	switch val := a.(type) {
	case bool:
		return strconv.AppendBool(buf, val)
	case float32:
		return strconv.AppendFloat(buf, float64(val), 'f', 9, 32)
	case float64:
		return strconv.AppendFloat(buf, val, 'f', 9, 64)
	case int:
		return strconv.AppendInt(buf, int64(val), 10)
	case int8:
		return strconv.AppendInt(buf, int64(val), 10)
	case int16:
		return strconv.AppendInt(buf, int64(val), 10)
	case int32:
		return strconv.AppendInt(buf, int64(val), 10)
	case int64:
		return strconv.AppendInt(buf, val, 10)
	case uint:
		return strconv.AppendUint(buf, uint64(val), 10)
	case uint8:
		return strconv.AppendUint(buf, uint64(val), 10)
	case uint16:
		return strconv.AppendUint(buf, uint64(val), 10)
	case uint32:
		return strconv.AppendUint(buf, uint64(val), 10)
	case uint64:
		return strconv.AppendUint(buf, val, 10)
	case uintptr:
		return strconv.AppendUint(buf, uint64(val), 10)
	case string:
		return strconv.AppendQuote(buf, val)
	case []byte:
		return strconv.AppendQuote(buf, string(val))
	default: // complex64 complex128
		return strconv.AppendQuote(buf, fmt.Sprint(val))
	}
}
