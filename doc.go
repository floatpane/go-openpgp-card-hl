// Package cardhl is a high-level signer and decryptor for OpenPGP smartcards
// (YubiKey, Nitrokey, and other OpenPGP-applet cards) over PC/SC.
//
// It wraps the low-level transport (cunicu.li/go-iso7816 +
// cunicu.li/go-openpgp-card) and the OpenPGP packet layer
// (github.com/ProtonMail/go-crypto) behind three operations — sign, decrypt,
// and list-keys — with errors that tell a human what to do next ("is pcscd
// running?", "is the YubiKey plugged in?") instead of leaking raw APDU codes.
//
// The signing path produces a detached, ASCII-armored OpenPGP signature over
// arbitrary bytes. That is exactly what git commit signing, mail
// (multipart/signed), and age-plugin-style tooling need; higher-level framing
// (MIME, the git signature envelope) is left to the caller.
//
// # Quick start
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
// # Security model
//
// The private key never leaves the card; signing and decryption happen on the
// device. The PIN (PW1) is sent to the card to authorize each operation. This
// library does not cache PINs, touch the filesystem, or talk to gpg-agent.
package cardhl
