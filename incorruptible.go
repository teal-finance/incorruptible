// Copyright (c) 2022 Teal.Finance contributors
// This file is part of Teal.Finance/incorruptible licensed under the MIT License.
// SPDX-License-Identifier: MIT

package incorruptible

import (
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/teal-finance/incorruptible/aead"
	"github.com/teal-finance/incorruptible/dtoken"

	// baseN "github.com/teal-finance/BaseXX/base92" // toggle package with same interface.
	baseN "github.com/mtraver/base91"
)

type Incorruptible struct {
	writeErr WriteHTTP
	Expiry   time.Duration
	SetIP    bool          // If true => put the remote IP in the token.
	dtoken   dtoken.DToken // dtoken is the "tiny" token.
	cookie   http.Cookie
	IsDev    bool
	cipher   aead.Cipher
	magic    byte
	baseN    *baseN.Encoding
}

const (
	authScheme        = "Bearer "
	secretTokenScheme = "i:" // See RFC 8959, "i" means "incorruptible" format
	prefixScheme      = authScheme + secretTokenScheme

	// secondsPerYear = 31556952 // average including leap years
	// nsPerYear      = secondsPerYear * 1_000_000_000.
)

func New(urls []*url.URL, secretKey []byte, expiry time.Duration, setIP bool, writeErr WriteHTTP) *Incorruptible {
	if len(urls) == 0 {
		log.Panic("No urls => Cannot set Cookie domain")
	}

	secure, dns, path := extractMainDomain(urls[0])

	cipher, err := aead.New(secretKey)
	if err != nil {
		log.Panic("AES NewCipher ", err)
	}

	if writeErr == nil {
		writeErr = defaultWriteHTTP
	}

	incorr := Incorruptible{
		writeErr: writeErr,
		Expiry:   expiry,
		SetIP:    setIP,
		// the "tiny" token is the default token
		dtoken: dtoken.DToken{Expiry: 0, IP: nil, Values: nil},
		cookie: emptyCookie("session", secure, dns, path),
		IsDev:  isLocalhost(urls),
		cipher: cipher,
		magic:  secretKey[0],
		baseN:  baseN.NewEncoding(noSpaceDoubleQuoteSemicolon),
	}

	// serialize the "tiny" token (with encryption and Base91 encoding)
	base91, err := incorr.Encode(incorr.dtoken)
	if err != nil {
		log.Panic("Encode(emptyToken) ", err)
	}

	// insert this generated token in the cookie
	incorr.cookie.Value = secretTokenScheme + base91

	return &incorr
}

func (incorr *Incorruptible) NewCookie(dt dtoken.DToken) (http.Cookie, error) {
	base91, err := incorr.Encode(dt)
	if err != nil {
		return incorr.cookie, err
	}

	cookie := incorr.NewCookieFromToken(base91, dt.ExpiryTime())
	return cookie, nil
}

func (incorr *Incorruptible) NewCookieFromToken(base91 string, expiry time.Time) http.Cookie {
	cookie := incorr.cookie
	cookie.Value = secretTokenScheme + base91

	if expiry.IsZero() {
		cookie.Expires = time.Time{} // time.Now().Add(nsPerYear)
	} else {
		cookie.Expires = expiry
	}

	return cookie
}

func (incorr *Incorruptible) SetCookie(w http.ResponseWriter, r *http.Request) dtoken.DToken {
	dt := incorr.dtoken     // copy the "tiny" token
	cookie := incorr.cookie // copy the default cookie

	if incorr.Expiry <= 0 {
		cookie.Expires = time.Time{} // time.Now().Add(nsPerYear)
	} else {
		cookie.Expires = time.Now().Add(incorr.Expiry)
		dt.SetExpiry(incorr.Expiry)
	}

	if incorr.SetIP {
		err := dt.SetRemoteIP(r)
		if err != nil {
			log.Panic(err)
		}
	}

	requireNewEncoding := (incorr.Expiry > 0) || incorr.SetIP
	if requireNewEncoding {
		base91, err := incorr.Encode(dt)
		if err != nil {
			log.Panic(err)
		}
		cookie.Value = secretTokenScheme + base91
	}

	http.SetCookie(w, &cookie)
	return dt
}

// Cookie returns the internal cookie (for test purpose).
func (incorr *Incorruptible) Cookie(int) *http.Cookie {
	return &incorr.cookie
}

// URL schemes.
const (
	HTTP  = "http"
	HTTPS = "https"
)

func extractMainDomain(url *url.URL) (secure bool, dns, path string) {
	if url == nil {
		log.Panic("No URL => Cannot set Cookie domain")
	}

	switch {
	case url.Scheme == HTTP:
		secure = false

	case url.Scheme == HTTPS:
		secure = true

	default:
		log.Panic("Unexpected scheme in ", url)
	}

	return secure, url.Hostname(), url.Path
}

func isLocalhost(urls []*url.URL) bool {
	if len(urls) > 0 && urls[0].Scheme == "http" {
		host, _, _ := net.SplitHostPort(urls[0].Host)
		if host == "localhost" {
			log.Print("Incorr in DevMode accepts missing/invalid token ", urls[0])
			return true
		}
	}

	log.Print("Incorr in ProdMode requires valid token because no http://localhost in first of ", urls)
	return false
}

func emptyCookie(name string, secure bool, dns, path string) http.Cookie {
	if path != "" && path[len(path)-1] == '/' {
		path = path[:len(path)-1] // remove trailing slash
	}

	return http.Cookie{
		Name:       name,
		Value:      "", // emptyCookie because no token
		Path:       path,
		Domain:     dns,
		Expires:    time.Time{},
		RawExpires: "",
		MaxAge:     0, // secondsPerYear,
		Secure:     secure,
		HttpOnly:   true,
		SameSite:   http.SameSiteStrictMode,
		Raw:        "",
		Unparsed:   nil,
	}
}
