<div align="center">

# go-openpgp-card-hl

**High-level OpenPGP smartcard signer & decryptor for Go — YubiKey, Nitrokey, and friends.**

[![Go Version](https://img.shields.io/github/go-mod/go-version/floatpane/go-openpgp-card-hl)](https://golang.org)
[![Go Reference](https://pkg.go.dev/badge/github.com/floatpane/go-openpgp-card-hl.svg)](https://pkg.go.dev/github.com/floatpane/go-openpgp-card-hl)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/floatpane/go-openpgp-card-hl)](https://github.com/floatpane/go-openpgp-card-hl/releases)
[![CI](https://github.com/floatpane/go-openpgp-card-hl/actions/workflows/ci.yml/badge.svg)](https://github.com/floatpane/go-openpgp-card-hl/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

`go-openpgp-card-hl` is the friendly front door to an OpenPGP smartcard. It
wraps the low-level transport ([`cunicu.li/go-iso7816`](https://github.com/cunicu/go-iso7816)
+ [`cunicu.li/go-openpgp-card`](https://github.com/cunicu/go-openpgp-card)) and
the OpenPGP packet layer ([`ProtonMail/go-crypto`](https://github.com/ProtonMail/go-crypto))
behind three operations — **sign**, **decrypt**, **list-keys** — with errors
that tell a human what to do next instead of leaking raw APDU status words.

The private key never leaves the card. Signing and decryption run on the device.

## Features

- **Detached, armored signatures.** `Sign` produces a standard
  `-----BEGIN PGP SIGNATURE-----` block over arbitrary bytes — exactly what git
  commit signing, `multipart/signed` mail, and age-plugin-style tooling need.
- **EdDSA, RSA, and ECDSA signing.** The signature packet is built to the right
  MPI shape per algorithm; the card just signs the digest.
- **RSA decryption.** `Decrypt` unwraps the session key on the card via
  `crypto.Decrypter` and hands the symmetric layer to `go-crypto`.
- **Structured card info.** `Info` / `ListKeys` give you manufacturer, serial,
  cardholder, and each slot's algorithm, status, and fingerprint.
- **Actionable errors.** `ErrNoPCSC`, `ErrNoCard`, `ErrPIN`, `ErrUnsupportedKey`
  — matchable with `errors.Is`, each wrapping a message a user can act on.

## Install

```bash
go get github.com/floatpane/go-openpgp-card-hl
```

Requires Go 1.26+, a PC/SC stack (`pcscd` on Linux), and an OpenPGP smartcard.

## Usage

### Sign

```go
package main

import (
    "fmt"
    "log"
    "os"

    cardhl "github.com/floatpane/go-openpgp-card-hl"
)

func main() {
    card, err := cardhl.Open()
    if err != nil {
        log.Fatal(err) // e.g. "no OpenPGP smartcard found: … plug in your YubiKey"
    }
    defer card.Close()

    // The signing key's public half supplies the signature-packet metadata.
    pub, err := cardhl.LoadPublicKey("key.asc")
    if err != nil {
        log.Fatal(err)
    }

    sig, err := card.Sign([]byte("hello, world"), os.Getenv("PIN"), pub)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(string(sig)) // -----BEGIN PGP SIGNATURE-----
}
```

### List keys

```go
info, err := card.Info()
if err != nil {
    log.Fatal(err)
}
fmt.Print(info) // Manufacturer / Serial / Version / Cardholder / per-slot keys
```

### Decrypt (RSA)

```go
key, err := cardhl.LoadEntity("recipient.asc") // public key with an encryption subkey
if err != nil {
    log.Fatal(err)
}
plain, err := card.Decrypt(ciphertext, os.Getenv("PIN"), key)
if err != nil {
    log.Fatal(err)
}
```

> ECDH / Curve25519 decryption keys are not supported — the unwrap needs scalar
> access the card does not expose. Use `gpg-agent` for those. RSA works because
> `go-crypto` accepts a `crypto.Decrypter`.

## How signing works

`Sign` builds a v4 OpenPGP signature packet by hand: it assembles the hashed
subpackets (creation time, issuer key ID, issuer fingerprint), computes the
RFC 4880 hash over `data || hash-suffix || trailer`, and asks the card to sign
the digest. The raw signature is encoded into the right MPI form for the key's
algorithm (two MPIs for EdDSA/ECDSA, one for RSA) and wrapped in ASCII armor.

The signature covers `data` verbatim as a *binary document* (type `0x00`).
Higher-level framing — the MIME `multipart/signed` envelope, the git signature
format — is the caller's job; hash the bytes you want covered and pass them in.

## Documentation

Full API reference: [pkg.go.dev/github.com/floatpane/go-openpgp-card-hl](https://pkg.go.dev/github.com/floatpane/go-openpgp-card-hl)

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

The private key stays on the card. Report vulnerabilities privately via
[SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
