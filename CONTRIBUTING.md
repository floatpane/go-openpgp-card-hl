# Contributing to go-openpgp-card-hl

Thanks for your interest in contributing! This guide covers the basics.

## Getting Started

### Prerequisites

- [Go 1.26+](https://go.dev/dl/)
- A PC/SC stack for anything that touches hardware: `pcscd` + `libccid` on
  Linux, the built-in stack on macOS/Windows.
- An OpenPGP smartcard (YubiKey 5, Nitrokey, etc.) **only** for end-to-end
  testing. The unit tests are pure — they exercise the packet/MPI/ASN.1 code
  and do not require a card.

### Setup

```bash
git clone https://github.com/floatpane/go-openpgp-card-hl.git
cd go-openpgp-card-hl
go mod tidy
```

### Build & Test

```bash
go build ./...
go test ./...
```

The unit tests run without a card. If you have hardware, manual verification of
`Sign`, `Decrypt`, and `Info` against a real YubiKey/Nitrokey is hugely
appreciated in the PR description — note the card model, firmware, and key
algorithm you tested with.

### Linting

```bash
gofmt -l .
go vet ./...
golangci-lint run
```

## Making Changes

### Branch Naming

Create a branch from `master` using one of these prefixes:

- `feature/` — new functionality
- `fix/` — bug fixes
- `docs/` — documentation changes
- `refactor/` — code restructuring without behavior changes

### Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): short description
```

Common types: `feat`, `fix`, `docs`, `test`, `ci`, `chore`.

Examples:

```
feat(sign): support ECDSA NIST P-384 signing keys
fix(sign): strip leading zero bytes before computing MPI bit length
docs: document the RSA-only limitation of Decrypt
```

### Before Submitting a PR

1. `gofmt -l .` is clean.
2. `go vet ./...` is clean.
3. `go test ./...` passes (including the race detector: `go test -race ./...`).
4. Keep PRs focused — one logical change per PR.
5. Write a clear PR description: **what** changed and **why**. For crypto or
   packet-format changes, cite the relevant RFC section (RFC 4880 / RFC 9580).

### A note on cryptographic code

Most of this library is byte-level OpenPGP packet construction. Subtle bugs
here are signature forgeries, not crashes. If you change `buildSignaturePacket`,
`writeMPI`, `parseASN1Signature`, or the `Decrypt` path:

- Add or extend a test with concrete byte vectors.
- Cross-check the output against `gpg --list-packets` or `sq packet dump` where
  you can.
- Call out exactly which RFC requirement your bytes satisfy.

## Reporting Bugs

Open an issue using the bug report template. Include a minimal reproducer (a
byte slice, a failing test, or the `gpg`/`sq` command that disagrees with us),
expected vs. actual behavior, and your Go version, OS, and — if hardware is
involved — card model and key algorithm.

## Requesting Features

Open an issue using the feature request template. Describe the problem and your
proposed solution.

## AI Policy

We welcome contributions that use AI-assisted tools (Copilot, Claude, ChatGPT, etc.).
Contributors are fully responsible for any code they submit, regardless of how
it was written.

**What we expect:**

- **Understand what you submit.** You should be able to explain every line of
  your PR — doubly so for the packet-format and crypto code.
- **Review AI output carefully.** AI tools produce plausible-looking code that
  is sometimes subtly wrong, insecure, or off-pattern. Verify before committing.
- **No AI-generated issues, reviews, or comments.** Discussions should be
  genuine human communication.
- **No AI-generated tests that don't actually test anything.** Tests must
  validate behavior, not just exist for coverage.
- **Attribute when appropriate.** A brief mention in the PR description is
  appreciated but not required.

**What we won't accept:**

- Bulk PRs of AI-generated refactors or "improvements" that weren't requested.
- Code that introduces hallucinated dependencies, APIs, or patterns.
- Contributions where the author clearly doesn't understand the changes.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you agree to uphold a welcoming and respectful environment.
