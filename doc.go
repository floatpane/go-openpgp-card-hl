// Package cardhl is a high-level signer and decryptor for OpenPGP smartcards
// (YubiKey, Nitrokey, and other OpenPGP-applet cards) over PC/SC.
//
// It wraps the low-level transport (cunicu.li/go-iso7816 +
// cunicu.li/go-openpgp-card) and the OpenPGP packet layer
// (github.com/ProtonMail/go-crypto) behind five operations — Sign, Decrypt,
// SignMIME, DecryptMIME, and ListKeys — with errors that tell a human what to
// do next ("is pcscd running?", "is the YubiKey plugged in?") instead of
// leaking raw APDU codes.
//
// Sign produces a detached, ASCII-armored OpenPGP signature over arbitrary
// bytes (git commit signing, age-plugin-style tooling, etc.).
//
// SignMIME and DecryptMIME handle RFC 3156 PGP/MIME directly: SignMIME takes
// a raw MIME message and returns a multipart/signed message; DecryptMIME takes
// a multipart/encrypted message and returns the plaintext, with all MIME
// parsing and armor handling done inside the library.
//
// # Quick start — raw signing
//
//	card, err := cardhl.Open()
//	if err != nil {
//	    log.Fatal(err) // friendly, actionable message
//	}
//	defer card.Close()
//
//	pub, err := cardhl.LoadPublicKey("key.asc") // signing subkey metadata
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	sig, err := card.Sign(payload, pin, pub)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	os.Stdout.Write(sig) // -----BEGIN PGP SIGNATURE-----
//
// # Quick start — PGP/MIME
//
//	// Sign a raw MIME message and get back a multipart/signed message.
//	signed, err := card.SignMIME(rawMIMEMessage, pin, pub)
//
//	// Decrypt a multipart/encrypted message.
//	key, err := cardhl.LoadEntity("recipient.asc")
//	plain, err := card.DecryptMIME(encryptedMIMEMessage, pin, key)
//
// # Security model
//
// The private key never leaves the card; signing and decryption happen on the
// device. The PIN (PW1) is sent to the card to authorize each operation. This
// library does not cache PINs, touch the filesystem, or talk to gpg-agent.
package cardhl
