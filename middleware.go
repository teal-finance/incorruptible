// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

package incorruptible

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/teal-finance/incorruptible/tvalues"
)

// Set puts a "session" cookie when the request has no valid "incorruptible" token.
// The token is searched in the "session" cookie and in the first "Authorization" header.
// The "session" cookie (that is added in the response) contains a minimalist "incorruptible" token.
// Finally, Set stores the decoded token in the request context.
func (incorr *Incorruptible) Set(next http.Handler) http.Handler {
	log.Printf("Middleware IncorruptibleSet cookie %q MaxAge=%v setIP=%v",
		incorr.cookie.Name, incorr.cookie.MaxAge, incorr.SetIP)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tv, a := incorr.DecodeToken(r)
		if a != nil {
			// no valid token found => set a new token
			cookie, newDT, err := incorr.NewCookie(r)
			if err != nil {
				log.Print("Middleware IncorruptibleSet ", err)
				return
			}
			http.SetCookie(w, cookie)
			tv = newDT
		}
		next.ServeHTTP(w, tv.ToCtx(r))
	})
}

// Chk accepts requests only if it has a valid cookie.
// Chk does not verify the "Authorization" header.
// Use instead the Vet() middleware to also verify the "Authorization" header.
// Chk finally stores the decoded token in the request context.
// In dev. mode, Chk accepts requests without valid cookie but does not store invalid tokens.
func (incorr *Incorruptible) Chk(next http.Handler) http.Handler {
	log.Printf("Middleware IncorruptibleChk cookie DevMode=%v", incorr.IsDev)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tv, err := incorr.DecodeCookieToken(r)
		switch {
		case err == nil: // OK: put the token in the request context
			r = tv.ToCtx(r)
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
// Vet finally stores the decoded token in the request context.
// In dev. mode, Vet accepts requests without a valid token but does not store invalid tokens.
func (incorr *Incorruptible) Vet(next http.Handler) http.Handler {
	log.Printf("Middleware IncorruptibleVet cookie/bearer DevMode=%v", incorr.IsDev)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tv, err := incorr.DecodeToken(r)
		switch {
		case err == nil:
			r = tv.ToCtx(r) // put the token in the request context
		case !incorr.IsDev:
			incorr.writeErr(w, r, http.StatusUnauthorized, err...)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (incorr *Incorruptible) DecodeToken(r *http.Request) (tvalues.TValues, []any) {
	var tv tvalues.TValues
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
		if incorr.equalMinimalistToken(base91) {
			return tvalues.New(), nil
		}
		if tv, err[i] = incorr.Decode(base91); err[i] != nil {
			continue
		}
		if err[i] = tv.Valid(r); err[i] != nil {
			continue
		}
		return tv, nil
	}

	return tv, []any{
		fmt.Errorf("missing or invalid 'incorruptible' token in either "+
			"the '%s' cookie or the 1st 'Authorization' header", incorr.cookie.Name),
		"error_cookie", err[0],
		"error_bearer", err[1],
	}
}

func (incorr *Incorruptible) DecodeCookieToken(r *http.Request) (tvalues.TValues, error) {
	base91, err := incorr.CookieToken(r)
	if err != nil {
		return tvalues.TValues{}, err
	}
	if incorr.equalMinimalistToken(base91) {
		return tvalues.New(), nil
	}
	tv, err := incorr.Decode(base91)
	if err != nil {
		return tv, err
	}
	return tv, tv.Valid(r)
}

func (incorr *Incorruptible) DecodeBearerToken(r *http.Request) (tvalues.TValues, error) {
	base91, err := incorr.BearerToken(r)
	if err != nil {
		return tvalues.TValues{}, err
	}
	if incorr.equalMinimalistToken(base91) {
		return tvalues.New(), nil
	}
	tv, err := incorr.Decode(base91)
	if err != nil {
		return tv, err
	}
	return tv, tv.Valid(r)
}

// CookieToken returns the token (in base91 format) from the cookie.
func (incorr *Incorruptible) CookieToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie(incorr.cookie.Name)
	if err != nil {
		return "", err
	}

	// TODO: Add some other tests, but this may break specific usage:
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

// BearerToken returns the token (in base91 format) from the HTTP Authorization header.
func (incorr *Incorruptible) BearerToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", errors.New("no 'Authorization: " + prefixScheme + "xxxxxxxx' in the request header")
	}

	return trimBearerScheme(auth)
}

func trimTokenScheme(uri string) (string, error) {
	const schemeSize = len(tokenScheme)
	if len(uri) < schemeSize+Base91MinSize {
		return "", fmt.Errorf("token URI too short: %d < %d", len(uri), schemeSize+Base91MinSize)
	}
	if uri[:schemeSize] != tokenScheme {
		return "", fmt.Errorf("want token URI in format '"+tokenScheme+"xxxxxxxx' got len=%d", len(uri))
	}
	tokenBase91 := uri[schemeSize:]
	return tokenBase91, nil
}

func trimBearerScheme(auth string) (string, error) {
	const prefixSize = len(prefixScheme)
	if len(auth) < prefixSize+Base91MinSize {
		return "", fmt.Errorf("bearer too short: %d < %d", len(auth), prefixSize+Base91MinSize)
	}
	if auth[:prefixSize] != prefixScheme {
		return "", fmt.Errorf("want format '"+prefixScheme+"xxxxxxxx' got len=%d", len(auth))
	}
	tokenBase91 := auth[prefixSize:]
	return tokenBase91, nil
}

func printDebug(str string, err error) {
	if doPrint {
		log.Printf("Incorr%s: %v", str, err)
	}
}
