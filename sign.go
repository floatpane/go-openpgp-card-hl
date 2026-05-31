package cardhl

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	openpgp "cunicu.li/go-openpgp-card"
)

// Sign returns a detached, ASCII-armored OpenPGP signature over data, produced
// by the card's signing key.
//
// pin authorizes the signing operation (PW1). pub supplies the metadata that
// goes into the signature packet — key ID, fingerprint, and public-key
// algorithm — and must correspond to the key on the card; use LoadPublicKey or
// ParsePublicKey to obtain it from an exported public key.
//
// The signature covers data verbatim as a binary document (signature type
// 0x00). Callers building higher-level envelopes (multipart/signed, the git
// signature format) hash the bytes they want covered and pass them here.
//
// EdDSA, RSA, and ECDSA signing keys are supported.
func (c *Card) Sign(data []byte, pin string, pub *packet.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("%w: nil public key", ErrNoKey)
	}

	if err := c.pgp.VerifyPassword(openpgp.PW1, pin); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPIN, err)
	}

	priv, err := c.pgp.PrivateKey(openpgp.KeySign, pub.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoKey, err)
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: signing key does not implement crypto.Signer", ErrUnsupportedKey)
	}

	sigPacket, err := buildSignaturePacket(data, signer, pub)
	if err != nil {
		return nil, err
	}

	return armorSignature(sigPacket)
}

// LoadPublicKey reads an exported OpenPGP public key from path and returns the
// signing-capable key (a signing subkey if present, otherwise the primary
// key). Both ASCII-armored and binary keyrings are accepted.
func LoadPublicKey(path string) (*packet.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(bytes.NewReader(data))
}

// ParsePublicKey reads an exported OpenPGP public key from r and returns the
// signing-capable key. Both ASCII-armored and binary keyrings are accepted.
func ParsePublicKey(r io.Reader) (*packet.PublicKey, error) {
	entity, err := ParseEntity(r)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	for _, subkey := range entity.Subkeys {
		if subkey.Sig != nil && subkey.Sig.FlagsValid && subkey.Sig.FlagSign &&
			!subkey.PublicKey.KeyExpired(subkey.Sig, now) {
			return subkey.PublicKey, nil
		}
	}
	return entity.PrimaryKey, nil
}

// buildSignaturePacket creates a valid OpenPGP v4 binary signature packet over
// signedContent, signing the digest on the card via signer.
func buildSignaturePacket(signedContent []byte, signer crypto.Signer, pubKey *packet.PublicKey) ([]byte, error) {
	now := time.Now()
	hashAlgo := crypto.SHA256
	hashAlgoID := byte(8) // SHA-256 in OpenPGP

	// Hashed subpackets.
	var hashedSubpackets bytes.Buffer

	// Signature creation time (type 2).
	writeSubpacket(&hashedSubpackets, 2, func(buf *bytes.Buffer) {
		ts := make([]byte, 4)
		binary.BigEndian.PutUint32(ts, uint32(now.Unix()))
		buf.Write(ts)
	})

	// Issuer key ID (type 16).
	writeSubpacket(&hashedSubpackets, 16, func(buf *bytes.Buffer) {
		kid := make([]byte, 8)
		binary.BigEndian.PutUint64(kid, pubKey.KeyId)
		buf.Write(kid)
	})

	// Issuer fingerprint (type 33).
	writeSubpacket(&hashedSubpackets, 33, func(buf *bytes.Buffer) {
		buf.WriteByte(byte(pubKey.Version))
		buf.Write(pubKey.Fingerprint)
	})

	// Hash suffix (RFC 4880, Section 5.2.4).
	var hashSuffix bytes.Buffer
	hashSuffix.WriteByte(4)                       // version
	hashSuffix.WriteByte(0x00)                    // signature type: binary
	hashSuffix.WriteByte(byte(pubKey.PubKeyAlgo)) // public key algorithm
	hashSuffix.WriteByte(hashAlgoID)              // hash algorithm
	hsLen := hashedSubpackets.Len()
	hashSuffix.WriteByte(byte(hsLen >> 8))
	hashSuffix.WriteByte(byte(hsLen))
	hashSuffix.Write(hashedSubpackets.Bytes())

	// V4 hash trailer.
	trailer := hashSuffix.Bytes()
	var hashTrailer bytes.Buffer
	hashTrailer.WriteByte(4)    // version
	hashTrailer.WriteByte(0xff) // marker
	tLen := make([]byte, 4)
	binary.BigEndian.PutUint32(tLen, uint32(len(trailer)))
	hashTrailer.Write(tLen)

	// Hash signed content + hash suffix + trailer.
	hasher := hashAlgo.New()
	hasher.Write(signedContent)
	hasher.Write(trailer)
	hasher.Write(hashTrailer.Bytes())
	digest := hasher.Sum(nil)

	// Sign on the card.
	rawSig, err := signer.Sign(nil, digest, hashAlgo)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSign, err)
	}

	// Signature packet body.
	var body bytes.Buffer
	body.Write(trailer) // version + sig type + algo + hash algo + hashed subpackets

	// Unhashed subpackets (empty).
	body.WriteByte(0)
	body.WriteByte(0)

	// Hash tag (first 2 bytes of digest).
	body.WriteByte(digest[0])
	body.WriteByte(digest[1])

	// Signature MPIs, by algorithm.
	switch pubKey.PubKeyAlgo { //nolint:exhaustive
	case packet.PubKeyAlgoEdDSA:
		if len(rawSig) != 64 {
			return nil, fmt.Errorf("%w: unexpected EdDSA signature length %d", ErrSign, len(rawSig))
		}
		writeMPI(&body, rawSig[:32]) // r
		writeMPI(&body, rawSig[32:]) // s

	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly:
		writeMPI(&body, rawSig)

	case packet.PubKeyAlgoECDSA:
		r, s, err := parseASN1Signature(rawSig)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrSign, err)
		}
		writeMPI(&body, r)
		writeMPI(&body, s)

	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedKey, pubKey.PubKeyAlgo)
	}

	// Wrap in a new-format packet (signature, tag 2).
	var pkt bytes.Buffer
	bodyBytes := body.Bytes()
	pkt.WriteByte(0xC2)
	writeNewFormatLength(&pkt, len(bodyBytes))
	pkt.Write(bodyBytes)

	return pkt.Bytes(), nil
}

// armorSignature wraps a binary OpenPGP signature in ASCII armor.
func armorSignature(sigPacket []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, "PGP SIGNATURE", nil)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(sigPacket); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeSubpacket writes a single OpenPGP subpacket.
func writeSubpacket(w *bytes.Buffer, typ byte, writeContent func(*bytes.Buffer)) {
	var content bytes.Buffer
	writeContent(&content)
	length := content.Len() + 1 // +1 for type byte
	if length < 192 {
		w.WriteByte(byte(length))
	} else {
		length -= 192
		w.WriteByte(byte(length>>8) + 192)
		w.WriteByte(byte(length))
	}
	w.WriteByte(typ)
	w.Write(content.Bytes())
}

// writeMPI writes a big-endian integer as an OpenPGP MPI (2-byte bit count + data).
func writeMPI(w io.Writer, data []byte) {
	for len(data) > 0 && data[0] == 0 {
		data = data[1:]
	}
	if len(data) == 0 {
		data = []byte{0}
	}
	bitLen := uint16((len(data)-1)*8 + bitLength(data[0]))
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, bitLen)
	_, _ = w.Write(buf)
	_, _ = w.Write(data)
}

// bitLength returns the number of significant bits in a byte.
func bitLength(b byte) int {
	n := 0
	for b > 0 {
		n++
		b >>= 1
	}
	return n
}

// writeNewFormatLength writes an OpenPGP new-format packet body length.
func writeNewFormatLength(w *bytes.Buffer, length int) {
	switch {
	case length < 192:
		w.WriteByte(byte(length))
	case length < 8384:
		length -= 192
		w.WriteByte(byte(length>>8) + 192)
		w.WriteByte(byte(length))
	default:
		w.WriteByte(255)
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(length))
		_, _ = w.Write(buf)
	}
}

// parseASN1Signature extracts r and s from an ASN.1 DER encoded ECDSA signature.
//
// Each intermediate slice access is bounds-checked against len(der); a
// truncated or malformed signature produces a typed error rather than an
// index-out-of-range panic.
func parseASN1Signature(der []byte) (r, s []byte, err error) {
	// ASN.1 SEQUENCE { INTEGER r, INTEGER s }
	if len(der) < 6 || der[0] != 0x30 {
		return nil, nil, fmt.Errorf("invalid ASN.1 signature")
	}

	pos := 2 // skip SEQUENCE tag and length

	// Parse R.
	if pos >= len(der) || der[pos] != 0x02 {
		return nil, nil, fmt.Errorf("expected INTEGER tag for R")
	}
	pos++
	if pos >= len(der) {
		return nil, nil, fmt.Errorf("ASN.1 signature truncated before R length")
	}
	rLen := int(der[pos])
	pos++
	if pos+rLen > len(der) {
		return nil, nil, fmt.Errorf("ASN.1 signature truncated: R length overflow")
	}
	rVal := new(big.Int).SetBytes(der[pos : pos+rLen])
	pos += rLen

	// Parse S.
	if pos >= len(der) || der[pos] != 0x02 {
		return nil, nil, fmt.Errorf("expected INTEGER tag for S")
	}
	pos++
	if pos >= len(der) {
		return nil, nil, fmt.Errorf("ASN.1 signature truncated before S length")
	}
	sLen := int(der[pos])
	pos++
	if pos+sLen > len(der) {
		return nil, nil, fmt.Errorf("ASN.1 signature truncated: S length overflow")
	}
	sVal := new(big.Int).SetBytes(der[pos : pos+sLen])

	return rVal.Bytes(), sVal.Bytes(), nil
}
