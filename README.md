# 🍸 Incorruptible &emsp; &emsp; &emsp; [![GoDoc][i]][d] [![Go Report Card][b]][r]

The **Incorruptible** project provides
a safer, shorter, faster [Bearer Token][t]
for session cookie and `Authorization` HTTP header.
See the [limitations](#🚫-limitations).

[_Incorruptible_][d] is also a 🍸 [drink][m]
that the [_Garçon_ de café][w] likes to serve to clients.
See the [origin of the name](#🍸-name).

[i]: https://pkg.go.dev/badge/github.com/teal-finance/incorruptible.svg
[d]: https://pkg.go.dev/github.com/teal-finance/incorruptible "Go documentation for Incorruptible"
[b]: https://goreportcard.com/badge/github.com/teal-finance/incorruptible
[r]: https://goreportcard.com/report/github.com/teal-finance/incorruptible
[t]: https://www.rfc-editor.org/rfc/rfc6750.html
[c]: https://www.shakeitdrinkit.com/incorruptible-cocktail-1618.html
[m]: https://wikiless.org/wiki/Mocktail "Incorruptible is also a Mocktail: a cocktail without alcohol"
[w]: https://en.wiktionary.org/wiki/garçon_de_café

![logo](docs/incorruptible.png)

## 🎯 Target

- **Safer**: State-of-the-art cipher configuration,
  conveying of expiration time and client IP,
  shuffled BasE91 alphabet, salt
  and random padding.

- **Shorter**: BasE91-encoded (shorter than Base64),
  optimized data encoding (no string keys) and adaptive compression.
  The smallest token is 27 bytes long at default settings.

- **Faster**: AES-128 (no RSA),
  hardwired encryption (AMD/Intel processors)
  and CPU-friendly serializer.

## 👶 Motivation

At Teal.Finance, our cookies were based on [JWT][q] and [gorilla/session][s].
The JWT is well standardized.
We use the usual way: JSON, Base64, RSA, HMAC-SHA256…
This is not very fast and generates large tokens:
the long JSON string is converted into Base64 text,
to which the signature stuff is appended.

With the session cookie purpose, we are free to innovate.
We love challenges.
As a hobby we tried to replace [gorilla/session][s].
The result is _Incorruptible_. 🎉

To make the implementation successful,
we updated our security knowledge
with recent state-of-the-art research.
We also benchmarked Base64/Ascii85/BasE91/Base92 encoders.
We think we did a good job,
with a good tradeoff between
security, performance and low bandwidth.

[q]: https://github.com/teal-finance/quid
[s]: https://github.com/gorilla/sessions

## 🤫 Usage

Now, we use less JWT and more _Incorruptible_ tokens in production:

- JWT as an authentication provided by the [Quid][q] server (trusted third party).
- _Incorruptible_ as a session token (session cookie).

### JWT

The **JWT** is well suited when multiple servers manage the authentication:
it avoids sharing the private key.
We use the good old RSA, with a [32-bytes] key (256 bits).
The [Auth server][q] is the single holding the private key.
Thus, the backend does manage the user login,
because the signature provided by the authentication server is sufficient.
So our backend can be moderately secure (does not hold user data).
Only the authentication server requires high security
(for example, we uninstall the SSH daemon on the machine).

[32-bytes]: https://crypto.stackexchange.com/q/34864#34866

### _Incorruptible_

We use _Incorruptible_ when the backend manages alone
its relationship with the frontend.
The secret is known only by the backend
(it does not need to be shared).

## 🔐 Encryption

The current trend toward symmetric encryption
prefers ChaCha20 / Poly1305 (server-side).
In addition to its cryptographic qualities,
ChaCha20 is easy to configure and requires
few CPU/memory resources.

On the other hand, on AMD and Intel processors,
AES is faster (optimized instructions).
In addition, the Go crypto allows to configure
AES in a simple and secure way.

Currently, we plan to use only AMD/Intel hardware (this may change).
Therefore, we currently prefer hardwired AES instructions
than ChaCha20 / Poly1305 (as chosen by Wireguard).

We place more emphasis on mastering
the encryption configuration than on performance.
See also <https://go.dev/blog/tls-cipher-suites>.

Therefore, this package currently uses only AES-GCM.
The key is 128 bits, since 256 bits are not yet relevant
(this may also change).

The encryption depends on standard Go only.
The `"math/rand"` package is used when a strong random generator is not required.
The user should call `rand.Seed()` to randomize the `"math/rand"` generator.
In the future, _Incorruptible_ may use something like [fastrand] if relevant.

Please share your thoughts on security or other topics.

[fastrand]: https://github.com/zhangyunhao116/fastrand

## 🍪 Encoding format

The serialization uses a format
designed for the specific _Incorruptible_ needs.
The format is composed of:

- Magic code (1 byte)
- Random salt (1 byte)
- Header bits (1 byte)
- Expiration time (from 0 to 4 bytes)
- Client IP (0, 4 or 16 bytes)
- Conveyed values, up to 31 values (from 0 to 7900 bytes)
- Optional random padding (padding length is also random)

See also <https://pkg.go.dev/github.com/teal-finance/incorruptible/format>.

The precision of the expiration time is defined
at build time with [constants in the source code][c2].
The default encoding size is 24 bits,
which gives a range of 10 years with an accuracy of 20 seconds.
The [configuration constants][c1]
allow easy decrease/increase of the storage from 1 to 4 bytes,
reducing/improving the timing precision.

A random 32-bits padding can also be appended.
This feature is currently disabled,
but can be activated [in the source code][c2].

If the token is too long, its payload
is compressed using [Snappy S2][s2].

[s2]: https://www.reddit.com/r/golang/comments/nziwb1/s2_fully_snappy_compatible_compression_faster_and/
[c1]: https://github.com/teal-finance/incorruptible/blob/main/format/coding/expiry.go#L13
[c2]: https://github.com/teal-finance/incorruptible/blob/main/format/marshal.go

Then, the whole data bytes are encrypted with AES-GCM 128 bits.
This encryption adds 16 bytes including the authentication bytes.

Finally, the cipher-text is BasE91 encoded,
which produces cookie-friendly tokens
at the cost of increasing the size by 19% (³⁄₁₆).
By comparison, Base64 and Ascii85 increase the size
by 33% and 25% respectively.

In the end, the minimum required 3 bytes (Magic+Salt+Header)
becomes a 27-bytes long _Incorruptible_ token (BasE91).

## 🚫 Limitations

_Incorruptible_ works perfectly with a single server.
The secrets can be stored in a data vault,
or randomly generated at startup time.

But, with multiple servers
(load-balancer, authentication server)
the encryption key must be shared.

Secrets sharing is a weak link in the security chain.
In this last case, JWT/CWT are preferable.
See also [Quid][q], a JWT authentication server
with signatures verified by public keys.

## 🍸 Name

The name _Incorruptible_ comes from the [incorruptible][c] drink,
a [mocktail][m] containing lemonade, grapefruit, and orange juice.

The _Incorruptible_ project has been originally implemented
as part of the [Teal.Finance/Garcon][g] server.
In French, "Garcon" _(garçon)_ is a 💁‍♂️ waiter,
serving drinks to clients. 😉

We wanted a name for a drink without alcohol, using a single word,
and understandable in different languages.
So _Incorruptible_ was our best choice at that time.

[g]: https://github.com/teal-finance/garcon

## ✨ Contributions welcome

This new project needs your help to get better.
Please suggest your improvements,
or even further refactoring.

We welcome contributions in many forms,
and there is always plenty to do!

## 🗣️ Feedback

If you have some suggestions, or need a new feature,
please contact us, by opening an [issue],
or at Teal.Finance@pm.me /
[@TealFinance](https://twitter.com/TealFinance).

Feel free to [pull a request][pr] too.
Your contributions are welcome. :wink:

[issue]: https://github.com/teal-finance/incorruptible/issues
[pr]: https://github.com/teal-finance/incorruptible/pulls

## 🗽 Copyright and license

Copyright (c) 2022 Teal.Finance/incorruptible contributors

Teal.Finance/incorruptible is free software,
and may be redistributed and/or modified
under the terms of the MIT License.
SPDX-License-Identifier: MIT

Teal.Finance/incorruptible is distributed
in the hope that it will be useful,
but WITHOUT ANY WARRANTY; even without the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

See the [LICENSE](LICENSE) file (alongside the source files)
or <https://opensource.org/licenses/MIT>.
