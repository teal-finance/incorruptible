// Copyright (c) 2022 Teal.Finance contributors
// This file is part of Teal.Finance/Incorruptible, a tiny cookie token.
// SPDX-License-Identifier: LGPL-3.0-or-later
// Teal.Finance/Incorruptible is free software under the GNU LGPL
// either version 3 or any later version, at the licensee's option.
// See the LICENSE file or <https://www.gnu.org/licenses/lgpl-3.0.html>

package incorruptible

import (
	"net/http"
	"strconv"
)

type WriteHTTP func(w http.ResponseWriter, r *http.Request, statusCode int, values ...any)

func defaultWriteJSON(w http.ResponseWriter, r *http.Request, statusCode int, values ...any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)

	if len(values) == 0 {
		return
	}
	message, ok := values[0].(string)
	if !ok {
		return
	}

	b := make([]byte, 0, 300)
	b = append(b, []byte(`{"error":`)...)
	b = strconv.AppendQuote(b, message)

	if r != nil {
		b = append(b, []byte(",\n"+`"path":`)...)
		b = strconv.AppendQuote(b, r.URL.Path)
		if r.URL.RawQuery != "" {
			b = append(b, []byte(",\n"+`"query":`)...)
			b = strconv.AppendQuote(b, r.URL.RawQuery)
		}
	}

	b = append(b, '}')
	b = append(b, '\n')
	_, _ = w.Write(b)
}
