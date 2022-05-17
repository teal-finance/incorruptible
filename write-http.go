// Copyright (c) 2022 Teal.Finance contributors
// This file is part of Teal.Finance/incorruptible licensed under the MIT License.
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

	b := make([]byte, 0, 1024)
	b = append(b, '{')

	if len(messages) > 0 {
		b = appendMessages(b, messages)
	}

	if r != nil {
		if len(messages) > 0 {
			b = append(b, ',')
			b = append(b, '\n')
		}
		b = appendURL(b, r.URL)
	}

	b = append(b, '}')
	_, _ = w.Write(b)
}

func appendMessages(b []byte, messages []any) []byte {
	b = append(b, []byte(`"error":`)...)
	b = appendKey(b, messages[0])

	for i := 1; i < len(messages); i += 2 {
		b = append(b, ',')
		b = append(b, '\n')
		b = appendKey(b, messages[i])
		b = append(b, ':')
		if i+1 < len(messages) {
			b = appendValue(b, messages[i+1])
		} else {
			b = append(b, '0')
		}
	}

	return b
}

func appendURL(b []byte, u *url.URL) []byte {
	b = append(b, []byte(`"path":`)...)
	b = strconv.AppendQuote(b, u.Path)
	if u.RawQuery != "" {
		b = append(b, []byte(",\n"+`"query":`)...)
		b = strconv.AppendQuote(b, u.RawQuery)
	}
	return b
}

func appendKey(b []byte, a any) []byte {
	switch v := a.(type) {
	case string:
		return strconv.AppendQuote(b, v)
	case []byte:
		return strconv.AppendQuote(b, string(v))
	default:
		return strconv.AppendQuote(b, fmt.Sprint(v))
	}
}

func appendValue(b []byte, a any) []byte {
	switch v := a.(type) {
	case bool:
		return strconv.AppendBool(b, v)
	case float32:
		return strconv.AppendFloat(b, float64(v), 'f', 9, 32)
	case float64:
		return strconv.AppendFloat(b, v, 'f', 9, 64)
	case int:
		return strconv.AppendInt(b, int64(v), 10)
	case int8:
		return strconv.AppendInt(b, int64(v), 10)
	case int16:
		return strconv.AppendInt(b, int64(v), 10)
	case int32:
		return strconv.AppendInt(b, int64(v), 10)
	case int64:
		return strconv.AppendInt(b, int64(v), 10)
	case uint:
		return strconv.AppendUint(b, uint64(v), 10)
	case uint8:
		return strconv.AppendUint(b, uint64(v), 10)
	case uint16:
		return strconv.AppendUint(b, uint64(v), 10)
	case uint32:
		return strconv.AppendUint(b, uint64(v), 10)
	case uint64:
		return strconv.AppendUint(b, uint64(v), 10)
	case uintptr:
		return strconv.AppendUint(b, uint64(v), 10)
	case string:
		return strconv.AppendQuote(b, v)
	case []byte:
		return strconv.AppendQuote(b, string(v))
	default: // complex64 complex128
		return strconv.AppendQuote(b, fmt.Sprint(v))
	}
}
