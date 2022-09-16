// Copyright 2022 Teal.Finance/incorruptible contributors
// This file is part of Teal.Finance/incorruptible
// a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

package incorruptible

import (
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/binary"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"path"
	"time"

	// baseN "github.com/teal-finance/BaseXX/base92" // use another package with same interface.
	baseN "github.com/mtraver/base91"

	"github.com/teal-finance/emo"
)

//nolint:gochecknoglobals // global logger
var log = emo.NewZone("incorr")

type Incorruptible struct {
	writeErr WriteErr
	SetIP    bool // If true => put the remote IP in the token.
	cookie   http.Cookie
	// IsDev    bool
	cipher cipher.AEAD
	magic  byte
	baseN  *baseN.Encoding
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
		log.Panic("No URL => Cannot set cookie attributes: Domain, Secure and Path")
	}

	secure, dns, dir := extractMainDomain(urls[0])

	c, err := NewAESCipher(secretKey)
	if err != nil {
		log.Panic("AES NewCipher", err)
	}

	// initialize the random generator with a reproducible secret seed
	resetRandomGenerator(secretKey)
	magic := magicCode()
	encodingAlphabet := shuffle(noSpaceDoubleQuoteSemicolon)

	// reset the random generator with a strong random seed
	resetRandomGenerator(nil)

	incorr := Incorruptible{
		writeErr: writeErr,
		SetIP:    setIP,
		cookie:   emptyCookie(cookieName, secure, dns, dir, maxAge),
		// IsDev:    isLocalhost(urls),
		cipher: c,
		magic:  magic,
		baseN:  baseN.NewEncoding(encodingAlphabet),
	}

	incorr.addMinimalistToken()

	log.Securityf("Cookie %s Domain=%v Path=%v Max-Age=%v Secure=%v SameSite=%v HttpOnly=%v Value=%d bytes",
		incorr.cookie.Name, incorr.cookie.Domain, incorr.cookie.Path, incorr.cookie.MaxAge,
		incorr.cookie.Secure, incorr.cookie.SameSite, incorr.cookie.HttpOnly, len(incorr.cookie.Value))

	return &incorr
}

func (incorr *Incorruptible) addMinimalistToken() {
	if !incorr.useMinimalistToken() {
		return
	}

	// serialize a minimalist token
	// including encryption and Base91-encoding
	token, err := incorr.Encode(EmptyTValues())
	if err != nil {
		log.Panic(err)
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

// resetRandomGenerator resets the "math.rand" generator from 16 bytes.
// This function is used to initialize the random generator with a reproducible secret seed.
// If no bytes are passed, resetRandomGenerator resets the "math.rand" generator with a strong random seed.
func resetRandomGenerator(bytes []byte) {
	if len(bytes) == 0 {
		bytes = make([]byte, 16)
		_, err := crand.Read(bytes)
		if err != nil {
			log.Panic(err)
		}
	}
	seed := binary.BigEndian.Uint64(bytes)
	seed += binary.BigEndian.Uint64(bytes[8:])
	mrand.Seed(int64(seed))
}

func magicCode() byte {
	//nolint:gosec // Reproduce MagicCode from same secret seed
	return byte(mrand.Int63())
}

// shuffle randomizes order of the input string.
func shuffle(s string) string {
	r := []rune(s)
	mrand.Shuffle(len(r), func(i, j int) { r[i], r[j] = r[j], r[i] })
	return string(r)
}

// NewCookie creates a new cookie based on default values.
// the HTTP request parameter is used to get the remote IP (only when incorr.SetIP is true).
func (incorr *Incorruptible) NewCookie(r *http.Request, keyValues ...KVal) (*http.Cookie, TValues, error) {
	cookie := incorr.cookie // local copy of the default cookie

	tv, err := incorr.NewTValues(r)
	if err != nil {
		return &cookie, tv, err
	}

	if !incorr.useMinimalistToken() || (len(keyValues) > 0) {
		err := tv.Set(keyValues...)
		if err != nil {
			return &cookie, tv, err
		}

		token, err := incorr.Encode(tv)
		if err != nil {
			return &cookie, tv, err
		}

		cookie.Value = tokenScheme + token
	}

	return &cookie, tv, nil
}

func (incorr *Incorruptible) NewTValues(r *http.Request, keyValues ...KVal) (TValues, error) {
	var tv TValues

	if !incorr.useMinimalistToken() {
		tv.SetExpiry(incorr.cookie.MaxAge)
		if incorr.SetIP {
			err := tv.SetRemoteIP(r)
			if err != nil {
				return tv, err
			}
		}
	}

	err := tv.Set(keyValues...)
	return tv, err
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

// Cookie returns a pointer to the default cookie values.
// This can be used to customize some cookie values (may break),
// and also to facilitate testing.
func (incorr *Incorruptible) Cookie(_ int) *http.Cookie {
	return &incorr.cookie
}

func (incorr *Incorruptible) CookieName() string {
	return incorr.cookie.Name
}

// URL schemes.
const (
	HTTP  = "http"
	HTTPS = "https"
)

//nolint:nonamedreturns // we want to document the returned values.
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
		log.Panicf("Unexpected protocol scheme in %+v", u)
	}

	return secure, u.Hostname(), u.Path
}

func isLocalhost(urls []*url.URL) bool {
	if len(urls) > 0 && urls[0].Scheme == "http" {
		host, _, _ := net.SplitHostPort(urls[0].Host)
		if host == "localhost" {
			log.Security("DevMode accepts missing/invalid token from", urls[0])
			return true
		}
	}

	log.Security("ProdMode requires valid token: no http://localhost in first of", urls)
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

	// sameSite = Strict works when using two backends like:
	// localhost:3000 (node) and localhost:8080 (API)
	// https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie/SameSite
	const sameSite = http.SameSiteStrictMode

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
