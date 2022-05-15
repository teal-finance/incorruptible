// Copyright (c) 2022 Teal.Finance contributors
// Licensed under the EUPL either v1.2 or any later version, at the licensee's option.
// SPDX-License-Identifier: EUPL-1.2+
// See the LICENCE.md file or https://joinup.ec.europa.eu/page/eupl-text-11-12
// This file is part of Teal.Finance/Incorruptible, a tiny cookie token.

/*
Package incorruptible provides a safer, shorter, faster session cookie.

🎯 Purpose

- Safer because of random salt in the tokens
  and understandable/auditable source code.

- Shorter because of Base91 (no Base64),
  compression and index instead of key names.

- Faster because of AES (no RSA)
  and custom bar-metal serializer.

🍸 Name

The incorruptible is a mocktail with lemonade, grapefruit and orange juice.
(see www.shakeitdrinkit.com/incorruptible-cocktail-1618.html)

Incorruptible has been originally developed within the Garcon web/API server.
Garcon in French (garçon) is the waiter serving drinks to clients.
(see github.com/teal-finance/garcon)

🔐 Encryption

The current trend about symmetric encryption
prefers ChaCha20Poly1305 (server side).
In addition to its cryptographic qualities,
ChaCha20 is easy to configure, and requires
few CPU/memory resources.

On the other hand, on AMD and Intel processors,
AES is faster (optimized instructions).
Moreover, the Go crypto allows to configure
AES in an easy and safe way.

See also: https://go.dev/blog/tls-cipher-suites

Therefore this package currently uses only AES-GCM.
The key is 128 bits, because 256 bits is not yet relevant in 2022.
This may change in a future version… Please share your thoughts.

🍪 Session cookie

The serialization uses a format invented for the occasion
which is called "incorruptible"
(a mocktail that Garçon de café likes to serve).

The format is:
	* MagicCode (1 byte)
	* Radom (1 byte)
	* Presence bits (1 byte)
	* Expiry time (0 or 3 bytes)
	* Client IP (0, 4 or 16 bytes)
	* Custom values, up to 31 values (from 0 to 7900 bytes)

See https://pkg.go.dev/github.com/teal-finance/incorruptible/format

When the token is too long, its payload is compressed with Snappy S2.

Optionally, some random 32-bits padding can be appended.
This feature is currently disabled.

The expiry time is stored in 24 bits, providing 10 years range
with 20-second precision. Constants in the source code allow
to easily increase-decrease the storage to 2 or 4 bytes,
reducing/increasing the expiry precision.

Then, the whole data bytes are encrypted with AES-GCM 128 bits.
This adds 16 bytes of header, including the authentication.

Finally, the ciphertext is Base91 encoded, adding some more bytes.

In the end, an "incorruptible" of 3 bytes (the minimum)
becomes a Base91 of 22 bytes.

🚫 Limitations

It works very well with a single server:
the secrets could be generated at startup.

On the other hand, in an environment with load-balancer,
or with an authentication server, you have to share the encryption key.
In this last case, the Quid solution is to be preferred.
Quid provides JWT that signature can be verified with a public key.
*/
package incorruptible
