# Incorruptible [![Go Reference](https://pkg.go.dev/badge/github.com/teal-finance/incorruptible.svg "Go documentation for Incorruptible")](https://pkg.go.dev/github.com/teal-finance/incorruptible) [![Go Report Card](https://goreportcard.com/badge/github.com/teal-finance/incorruptible)](https://goreportcard.com/report/github.com/teal-finance/incorruptible)

The **Incorruptible** project provides a safer, shorter, faster
[Bearer Token](https://www.rfc-editor.org/rfc/rfc6750.html)
for session cookie and `Authorization` HTTP header.

[Incorruptible](https://www.shakeitdrinkit.com/incorruptible-cocktail-1618.html)
is also a [mocktail](https://wikiless.org/wiki/Mocktail)
that the [*Garçon* de café](https://en.wiktionary.org/wiki/garçon_de_café) likes to serve to clients.

![logo](docs/incorruptible.png)

## 🎯 Purpose

- Safer because of random salt, expiration time
  and client IP in the token.

- Shorter because of Base91 (no Base64),
  compression and indexed-access instead of key names.

- Faster because of AES (no RSA)
  and custom bar-metal serializer.

## 🍸 Name

The *Incorruptible* name originates from the
[incorruptible](https://www.shakeitdrinkit.com/incorruptible-cocktail-1618.html)
drink, a [mocktail](https://wikiless.org/wiki/Mocktail)
with lemonade, grapefruit and orange juice.

The Incorruptible token has been originally developed within the
[Teal.Finance/Garcon](https://github.com/teal-finance/garcon)
web/API server. In French, "Garcon" *(garçon)* is the waiter,
that sometimes serves drinks to clients.

We wanted a name of cocktail without alcohol, using one single word,
and understandable in different languages.

## 🔐 Encryption

The current trend about symmetric encryption
prefers ChaCha20Poly1305 (server side).
In addition to its cryptographic qualities,
ChaCha20 is easy to configure, and requires
few CPU/memory resources.

On the other hand, on AMD and Intel processors,
AES is faster (optimized instructions).
Moreover, the Go crypto allows to configure
AES in an easy and safe way.

See also <https://go.dev/blog/tls-cipher-suites>.

Therefore this package currently uses only AES-GCM.
The key is 128 bits, because 256 bits is not yet relevant in 2022.
This may change in a future version… Please share your thoughts.

## 🍪 Token for Cookie and Authorization

The serialization uses a format designed for the occasion.
The format is composed of:

- Magic code (1 byte)
- Radom (1 byte)
- Presence bits (1 byte)
- Expiry time (0 or 3 bytes)
- Client IP (0, 4 or 16 bytes)
- Custom values, up to 31 values (from 0 to 7900 bytes)

See also <https://pkg.go.dev/github.com/teal-finance/incorruptible/format>.

When the token is too long, its payload is compressed with Snappy S2.

Optionally, some random 32-bits padding can be appended.
This feature is currently disabled.

The expiry time is stored in 24 bits, providing 10 years range
with 20-second precision. Constants in the source code allow
to easily increase-decrease the storage to 2 or 4 bytes,
reducing/increasing the expiry precision.

Then, the whole data bytes are encrypted with AES-GCM 128 bits.
This adds 16 bytes of header, including the authentication.

Finally, the cipher-text is Base91 encoded, adding some more bytes.

In the end, an "incorruptible" of 3 bytes (the minimum)
becomes a Base91 of 24 bytes.

## 🚫 Limitations

It works very well with a single server:
the secrets could be generated at startup.

On the other hand, in an environment with load-balancer,
or with an authentication server, you have to share the encryption key.
In this last case, the Quid solution is to be preferred.
Quid provides JWT that signature can be verified with a public key.

## ✨ Contributions Welcome

This new project needs your help to become better.
Please propose your enhancements,
or even a further refactoring.

We welcome contributions in many forms,
and there's always plenty to do!

## 🗣️ Feedback

If you have some suggestions, or need a new feature,
please contact us, using the
[issues](https://github.com/teal-finance/incorruptible/issues),
or at Teal.Finance@pm.me or
[@TealFinance](https://twitter.com/TealFinance).

Feel free to propose a
[Pull Request](https://github.com/teal-finance/incorruptible/pulls),
your contributions are welcome. :wink:

## 🗽 Copyright and license

Copyright (c) 2022 Teal.Finance contributors

Teal.Finance/incorruptible is free software, and can be redistributed
and/or modified under the terms of the MIT License.
SPDX-License-Identifier: MIT

Teal.Finance/incorruptible is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

See the [LICENSE](LICENSE) file (alongside the source files)
or <https://opensource.org/licenses/MIT>.
