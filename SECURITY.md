# Security Policy

## Supported Versions

Only the latest release of go-openpgp-card-hl is supported with security updates.

## Reporting a Vulnerability

If you discover a security vulnerability in go-openpgp-card-hl, please report it
responsibly. **Do not open a public issue.**

Email us at [us@floatpane.com](mailto:us@floatpane.com) with:

- A description of the vulnerability
- Steps to reproduce the issue
- The potential impact
- Any suggested fixes (optional)

We will acknowledge your report within 48 hours and aim to provide a fix or
mitigation plan within 7 days, depending on severity.

## Scope

This policy covers the go-openpgp-card-hl codebase and its official releases.

Of particular interest:

- **Signature forgery / malleability.** Flaws in the hand-built v4 signature
  packet (`buildSignaturePacket`), MPI encoding (`writeMPI`), or the ECDSA
  ASN.1 parser (`parseASN1Signature`) that let an attacker influence what is
  signed, or produce a signature that verifies over content the card holder did
  not approve.
- **Crafted input panics.** Malformed DER signatures, public key files, or
  OpenPGP messages that produce panics, runaway allocations, or out-of-range
  access in `parseASN1Signature`, `ParsePublicKey`/`ParseEntity`, or `Decrypt`.
- **PIN handling.** Any path where the PW1 PIN is logged, retained, or sent to
  the card more than intended.
- **Decryption oracles.** Behavior in the RSA `Decrypt` path that could be used
  as a padding or timing oracle against the card.
- **Wrong-key operations.** A `Sign`/`Decrypt` succeeding against a key slot or
  recipient key other than the one the caller intended.

The private key material lives on the smartcard and is outside this library's
control; the card enforces PIN retry limits and touch policy. Third-party
dependencies (`go-iso7816`, `go-openpgp-card`, `go-crypto`) are outside our
direct control, but we will work to address reported issues in them as quickly
as possible.

## Disclosure

We ask that you give us reasonable time to address the issue before disclosing
it publicly. We are committed to crediting reporters in release notes (unless
you prefer to remain anonymous).
