package cardhl

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"os"

	pgpcrypto "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	openpgp "cunicu.li/go-openpgp-card"
)

// Decrypt decrypts an OpenPGP message with the card's decryption key and
// returns the plaintext.
//
// pin authorizes the DECIPHER operation (PW1 in mode 0x82). key is the
// message recipient's public key — its encryption subkey identifies which
// session key the card must unwrap; load it with LoadEntity or ParseEntity.
//
// Only RSA decryption keys are supported. The session-key unwrap for RSA runs
// through the card's crypto.Decrypter; the symmetric layer is handled in
// process. ECDH/Curve25519 decryption requires scalar access the card does not
// expose — use gpg-agent for those keys.
func (c *Card) Decrypt(ciphertext []byte, pin string, key *pgpcrypto.Entity) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: nil public key", ErrNoKey)
	}

	decSub := encryptionSubkey(key)
	if decSub == nil {
		return nil, fmt.Errorf("%w: no encryption subkey in public key", ErrNoKey)
	}

	switch decSub.PublicKey.PubKeyAlgo { //nolint:exhaustive
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSAEncryptOnly:
	default:
		return nil, fmt.Errorf(
			"%w: decryption is only supported for RSA keys (got %v); use gpg-agent for ECDH/Curve25519 keys",
			ErrUnsupportedKey, decSub.PublicKey.PubKeyAlgo,
		)
	}

	if err := c.pgp.VerifyPassword(openpgp.PW1forPSO, pin); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPIN, err)
	}

	priv, err := c.pgp.PrivateKey(openpgp.KeyDecrypt, decSub.PublicKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoKey, err)
	}
	dec, ok := priv.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("%w: decryption key does not implement crypto.Decrypter", ErrUnsupportedKey)
	}

	// Back the recipient's encryption subkey with the on-card decrypter. The
	// public half (and thus the key ID the PKESK references) comes straight
	// from the parsed public key, so go-crypto routes the session-key unwrap
	// to the card.
	decSub.PrivateKey = &packet.PrivateKey{PublicKey: *decSub.PublicKey, PrivateKey: dec}

	md, err := pgpcrypto.ReadMessage(bytes.NewReader(ciphertext), pgpcrypto.EntityList{key}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecrypt, err)
	}

	plain, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecrypt, err)
	}
	return plain, nil
}

// encryptionSubkey returns the first valid encryption subkey of e, or nil.
func encryptionSubkey(e *pgpcrypto.Entity) *pgpcrypto.Subkey {
	for i := range e.Subkeys {
		sk := &e.Subkeys[i]
		if sk.Sig != nil && sk.Sig.FlagsValid &&
			(sk.Sig.FlagEncryptCommunications || sk.Sig.FlagEncryptStorage) {
			return sk
		}
	}
	return nil
}

// LoadEntity reads an exported OpenPGP public key from path and returns the
// first entity. Both ASCII-armored and binary keyrings are accepted.
func LoadEntity(path string) (*pgpcrypto.Entity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseEntity(bytes.NewReader(data))
}

// ParseEntity reads an exported OpenPGP public key from r and returns the first
// entity. Both ASCII-armored and binary keyrings are accepted.
func ParseEntity(r io.Reader) (*pgpcrypto.Entity, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	entities, err := pgpcrypto.ReadArmoredKeyRing(bytes.NewReader(data))
	if err != nil {
		entities, err = pgpcrypto.ReadKeyRing(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBadKeyFile, err)
		}
	}
	if len(entities) == 0 {
		return nil, fmt.Errorf("%w: no keys in keyring", ErrBadKeyFile)
	}
	return entities[0], nil
}
