// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

package incorruptible

import (
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"path"
	"time"

	// baseN "github.com/teal-finance/BaseXX/base92" // use another package with same interface.
	baseN "github.com/mtraver/base91"
)

type Incorruptible struct {
	writeErr WriteErr
	SetIP    bool // If true => put the remote IP in the token.
	cookie   http.Cookie
	IsDev    bool
	cipher   Cipher
	magic    byte
	baseN    *baseN.Encoding
}

const (
	authScheme   = "Bearer "
	tokenScheme  = "i:" // See RFC 8959, here "i" means "incorruptible token format"
	prefixScheme = authScheme + tokenScheme
)

// New creates a new Incorruptible. The order of the parameters are consistent with garcon.NewJWTChecker (see Teal-Finance/Garcon).
// The Garcon middleware constructors use a garcon.Writer as first parameter.
// Please share your thoughts/feedback, we can still change that.
func New(writeErr WriteErr, urls []*url.URL, secretKey []byte, cookieName string, maxAge int, setIP bool) *Incorruptible {
	if writeErr == nil {
		writeErr = defaultWriteErr
	}

	if len(urls) == 0 {
		log.Panic("No urls => Cannot set Cookie domain")
	}

	secure, dns, dir := extractMainDomain(urls[0])

	cipher, err := NewAESCipher(secretKey)
	if err != nil {
		log.Panic("AES NewCipher ", err)
	}

	initRandomGenerator(secretKey)
	magic := magicCode()
	encodingAlphabet := shuffle(noSpaceDoubleQuoteSemicolon)

	incorr := Incorruptible{
		writeErr: writeErr,
		SetIP:    setIP,
		cookie:   emptyCookie(cookieName, secure, dns, dir, maxAge),
		IsDev:    isLocalhost(urls),
		cipher:   cipher,
		magic:    magic,
		baseN:    baseN.NewEncoding(encodingAlphabet),
	}

	incorr.addMinimalistToken()

	return &incorr
}

func (incorr *Incorruptible) addMinimalistToken() {
	if !incorr.useMinimalistToken() {
		return
	}

	// serialize a minimalist token
	// including encryption and Base91-encoding
	token, err := incorr.Encode(NewTValues())
	if err != nil {
		log.Panic("addMinimalistToken ", err)
	}

	// insert this generated token in the cookie
	incorr.cookie.Value = tokenScheme + token
}

func (incorr *Incorruptible) useMinimalistToken() bool {
	return (incorr.cookie.MaxAge <= 0) && (!incorr.SetIP)
}

// equalMinimalistToken compares with the default token.
func (incorr *Incorruptible) equalMinimalistToken(base91 string) bool {
	const schemeSize = len(tokenScheme) // to skip the token scheme
	return incorr.useMinimalistToken() && (base91 == incorr.cookie.Value[schemeSize:])
}

// initRandomGenerator initializes the random generator with a reproducible secret seed.
func initRandomGenerator(secretKey []byte) {
	seed := binary.BigEndian.Uint64(secretKey)
	seed += binary.BigEndian.Uint64(secretKey[8:])
	rand.Seed(int64(seed))
}

func magicCode() byte {
	//nolint:gosec // Reproduce MagicCode from same secret seed
	return byte(rand.Int63())
}

// shuffle randomizes order of the input string.
func shuffle(s string) string {
	r := []rune(s)
	rand.Shuffle(len(r), func(i, j int) { r[i], r[j] = r[j], r[i] })
	return string(r)
}

// NewCookie creates a new cookie based on default values.
// the HTTP request parameter is used to get the remote IP (only when incorr.SetIP is true).
func (incorr *Incorruptible) NewCookie(r *http.Request) (*http.Cookie, TValues, error) {
	cookie := incorr.cookie // local copy of the default cookie
	tv := NewTValues()

	if !incorr.useMinimalistToken() {
		tv.SetExpiry(cookie.MaxAge)
		if incorr.SetIP {
			err := tv.SetRemoteIP(r)
			if err != nil {
				return &cookie, tv, err
			}
		}
		token, err := incorr.Encode(tv)
		if err != nil {
			return &cookie, tv, err
		}
		cookie.Value = tokenScheme + token
	}

	return &cookie, tv, nil
}

func (incorr *Incorruptible) NewCookieFromValues(tv TValues) (*http.Cookie, error) {
	token, err := incorr.Encode(tv)
	if err != nil {
		return &incorr.cookie, err
	}
	cookie := incorr.NewCookieFromToken(token, tv.MaxAge())
	return cookie, nil
}

func (incorr *Incorruptible) NewCookieFromToken(token string, maxAge int) *http.Cookie {
	cookie := incorr.cookie
	cookie.Value = tokenScheme + token
	cookie.MaxAge = maxAge
	return &cookie
}

// DeadCookie returns an Incorruptible cookie without Value and with "Max-Age=0"
// in order to delete the Incorruptible cookie in the current HTTP session.
//
// Example:
//
//	func logout(w http.ResponseWriter, r *http.Request) {
//	    http.SetCookie(w, Incorruptible.DeadCookie())
//	}
func (incorr *Incorruptible) DeadCookie() *http.Cookie {
	cookie := incorr.cookie // local copy of the default cookie
	cookie.Value = ""
	cookie.MaxAge = -1 // MaxAge<0 means "delete cookie now"
	return &cookie
}

// Cookie returns a default cookie to facilitate testing.
func (incorr *Incorruptible) Cookie(_ int) *http.Cookie {
	return &incorr.cookie
}

// URL schemes.
const (
	HTTP  = "http"
	HTTPS = "https"
)

func extractMainDomain(u *url.URL) (secure bool, dns, dir string) {
	if u == nil {
		log.Panic("No URL => Cannot set Cookie domain")
	}

	switch {
	case u.Scheme == HTTP:
		secure = false

	case u.Scheme == HTTPS:
		secure = true

	default:
		log.Panic("Unexpected scheme in ", u)
	}

	return secure, u.Hostname(), u.Path
}

func isLocalhost(urls []*url.URL) bool {
	if len(urls) > 0 && urls[0].Scheme == "http" {
		host, _, _ := net.SplitHostPort(urls[0].Host)
		if host == "localhost" {
			log.Print("INF Incorruptible in DevMode accepts missing/invalid token ", urls[0])
			return true
		}
	}

	log.Print("INF Incorruptible in ProdMode requires valid token because no http://localhost in first of ", urls)
	return false
}

func emptyCookie(name string, secure bool, dns, dir string, maxAge int) http.Cookie {
	dir = path.Clean(dir)
	if dir == "." {
		dir = "/"
	}

	if name == "" {
		name = "session"
		for i := len(dir) - 2; i >= 0; i-- {
			if dir[i] == byte('/') {
				name = dir[i+1:]
				break
			}
		}
	}

	// cookie prefix for enhanced security
	if secure && name[0] != '_' {
		if dir == "/" {
			// "__Host-" when cookie has "Secure" flag, has no "Domain",
			// has "Path=/" and is sent from a secure origin.
			dns = ""
			name = "__Host-" + name
		} else {
			// "__Secure-" when cookie has "Secure" flag and is sent from a secure origin
			// "__Host-" is better than the "__Secure-" prefix.
			name = "__Secure-" + name
		}
	}

	// https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie/SameSite
	sameSite := http.SameSiteLaxMode
	if secure {
		sameSite = http.SameSiteStrictMode
	}

	return http.Cookie{
		Name:       name,
		Value:      "", // emptyCookie because no token
		Path:       dir,
		Domain:     dns,
		Expires:    time.Time{},
		RawExpires: "",
		MaxAge:     maxAge,
		Secure:     secure,
		HttpOnly:   true,
		SameSite:   sameSite,
		Raw:        "",
		Unparsed:   nil,
	}
}
