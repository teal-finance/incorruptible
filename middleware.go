// Copyright (c) 2022 Teal.Finance contributors
// This file is part of Teal.Finance/incorruptible licensed under the MIT License.
// SPDX-License-Identifier: MIT

package incorruptible

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/teal-finance/incorruptible/dtoken"
)

// Set puts a "session" cookie when the request has no valid "incorruptible" token.
// The token is searched the "session" cookie and in the first "Authorization" header.
// The "session" cookie (that is added in the response) contains the "tiny" token.
// Finally, Set stores the decoded token in the request context.
func (incorr *Incorruptible) Set(next http.Handler) http.Handler {
	log.Printf("Middleware SessionSet cookie %q %v setIP=%v",
		incorr.cookie.Name, incorr.Expiry.Truncate(time.Second), incorr.SetIP)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dt, err := incorr.DecodeToken(r)
		if err != nil {
			// no valid token found => set a new token
			dt = incorr.SetCookie(w, r)
		}
		next.ServeHTTP(w, dt.PutInCtx(r))
	})
}

// Chk accepts requests only if it has a valid cookie.
// Chk does not verify the "Authorization" header.
// See the Vet() function to also verify the "Authorization" header.
// Chk also stores the decoded token in the request context.
// In dev. testing, Chk accepts any request but does not store invalid tokens.
func (incorr *Incorruptible) Chk(next http.Handler) http.Handler {
	log.Printf("Middleware SessionChk cookie DevMode=%v", incorr.IsDev)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dt, err := incorr.DecodeCookieToken(r)
		switch {
		case err == nil: // OK: put the token in the request context
			r = dt.PutInCtx(r)
		case incorr.IsDev:
			printDebug("Chk DevMode no cookie", err)
		default:
			incorr.writeErr(w, r, http.StatusUnauthorized, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Vet accepts requests having a valid token either in
// the "session" cookie or in the first "Authorization" header.
// Vet also stores the decoded token in the request context.
// In dev. testing, Vet accepts any request but does not store invalid tokens.
func (incorr *Incorruptible) Vet(next http.Handler) http.Handler {
	log.Printf("Middleware SessionVet cookie/bearer DevMode=%v", incorr.IsDev)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dt, err := incorr.DecodeToken(r)
		switch {
		case err == nil:
			r = dt.PutInCtx(r) // put the token in the request context
		case !incorr.IsDev:
			incorr.writeErr(w, r, http.StatusUnauthorized, err...)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (incorr *Incorruptible) DecodeToken(r *http.Request) (dtoken.DToken, []any) {
	var dt dtoken.DToken
	var err [2]error

	for i := 0; i < 2; i++ {
		var base91 string
		if i == 0 {
			base91, err[0] = incorr.CookieToken(r)
		} else {
			base91, err[1] = incorr.BearerToken(r)
		}
		if err[i] != nil {
			continue
		}
		if incorr.equalDefaultToken(base91) {
			return incorr.dtoken, nil
		}
		if dt, err[i] = incorr.Decode(base91); err[i] != nil {
			continue
		}
		if err[i] = dt.Valid(r); err[i] != nil {
			continue
		}
		return dt, nil
	}

	return dt, []any{
		fmt.Errorf("missing or invalid 'incorruptible' token in either "+
			"the '%s' cookie or the 1st 'Authorization' header", incorr.cookie.Name),
		"error_cookie", err[0],
		"error_bearer", err[1]}
}

func (incorr *Incorruptible) DecodeCookieToken(r *http.Request) (dt dtoken.DToken, err error) {
	base91, err := incorr.CookieToken(r)
	if err != nil {
		return dt, err
	}
	if incorr.equalDefaultToken(base91) {
		return incorr.dtoken, nil
	}
	if dt, err = incorr.Decode(base91); err != nil {
		return dt, err
	}
	return dt, dt.Valid(r)
}

func (incorr *Incorruptible) DecodeBearerToken(r *http.Request) (dt dtoken.DToken, err error) {
	base91, err := incorr.BearerToken(r)
	if err != nil {
		return dt, err
	}
	if incorr.equalDefaultToken(base91) {
		return incorr.dtoken, nil
	}
	if dt, err = incorr.Decode(base91); err != nil {
		return dt, err
	}
	return dt, dt.Valid(r)
}

func (incorr *Incorruptible) CookieToken(r *http.Request) (base91 string, err error) {
	cookie, err := r.Cookie(incorr.cookie.Name)
	if err != nil {
		return "", err
	}

	// TODO: test if usable:
	// if !cookie.HttpOnly {
	// 	return "", errors.New("no HttpOnly cookie")
	// }
	// if cookie.SameSite != s.cookie.SameSite {
	// 	return "", fmt.Errorf("want cookie SameSite=%v but got %v", s.cookie.SameSite, cookie.SameSite)
	// }
	// if cookie.Secure != s.cookie.Secure {
	// 	return "", fmt.Errorf("want cookie Secure=%v but got %v", s.cookie.Secure, cookie.Secure)
	// }

	return trimTokenScheme(cookie.Value)
}

func (incorr *Incorruptible) BearerToken(r *http.Request) (base91 string, err error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", errors.New("no 'Authorization: " + prefixScheme + "xxxxxxxx' in the request header")
	}

	return trimBearerScheme(auth)
}

// equalDefaultToken compares with the default token
// by skiping the token scheme.
func (incorr *Incorruptible) equalDefaultToken(base91 string) bool {
	const n = len(secretTokenScheme)
	return (base91 == incorr.cookie.Value[n:])
}

func trimTokenScheme(uri string) (base91 string, err error) {
	const n = len(secretTokenScheme)
	if len(uri) < n+base92MinSize {
		return "", fmt.Errorf("token URI too short (%d bytes) want %d", len(uri), n+base92MinSize)
	}
	if uri[:n] != secretTokenScheme {
		return "", fmt.Errorf("want token URI '"+secretTokenScheme+"xxxxxxxx' got %q", uri)
	}
	return uri[n:], nil
}

func trimBearerScheme(auth string) (base91 string, err error) {
	const n = len(prefixScheme)
	if len(auth) < n+base92MinSize {
		return "", fmt.Errorf("bearer too short (%d bytes) want %d", len(auth), n+base92MinSize)
	}
	if auth[:n] != prefixScheme {
		return "", fmt.Errorf("want '"+prefixScheme+"xxxxxxxx' got %s", auth)
	}
	return auth[n:], nil
}

func printDebug(str string, err error) {
	if doPrint {
		log.Printf("Incorr%s: %v", str, err)
	}
}
