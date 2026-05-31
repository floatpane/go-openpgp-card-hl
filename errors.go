package cardhl

import "errors"

// Sentinel errors returned by this package. Use errors.Is to match them; the
// concrete error returned usually wraps one of these with extra context from
// the card or PC/SC layer.
var (
	// ErrNoPCSC is returned when the PC/SC daemon cannot be reached. On Linux
	// this almost always means pcscd is not running.
	ErrNoPCSC = errors.New("cannot connect to PC/SC daemon")

	// ErrNoCard is returned when no smartcard exposing the OpenPGP applet is
	// present on any reader.
	ErrNoCard = errors.New("no OpenPGP smartcard found")

	// ErrCardInit is returned when a card is present but the OpenPGP applet
	// could not be initialized.
	ErrCardInit = errors.New("failed to initialize OpenPGP card")

	// ErrPIN is returned when PIN (PW1) verification fails.
	ErrPIN = errors.New("PIN verification failed")

	// ErrNoKey is returned when the requested key slot (sign/decrypt) holds no
	// key, or no public-key material could be read for it.
	ErrNoKey = errors.New("no key in slot")

	// ErrUnsupportedKey is returned when the key's algorithm is not supported
	// for the requested operation.
	ErrUnsupportedKey = errors.New("unsupported key algorithm")

	// ErrSign is returned when the card refuses or fails a signing operation.
	ErrSign = errors.New("signing failed")

	// ErrDecrypt is returned when a message cannot be decrypted with the card's
	// decryption key.
	ErrDecrypt = errors.New("decryption failed")

	// ErrBadKeyFile is returned when a public key file cannot be parsed.
	ErrBadKeyFile = errors.New("could not parse public key")
)
