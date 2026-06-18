package cardhl

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strings"
	"time"

	pgpcrypto "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// randRead is overridable in tests to produce deterministic boundaries.
var randRead = rand.Read

// SignMIME creates a RFC 3156 multipart/signed MIME message from payload
// using the card's signing key.
//
// payload is a raw MIME message (headers + CRLF + body). The result is a
// new message with the same transport headers and a multipart/signed body
// containing the original body as the first part and the detached PGP
// signature as the second.
//
// pub must be the signing-capable public key corresponding to the card's
// sign slot — obtained via LoadPublicKey or ParsePublicKey.
func (c *Card) SignMIME(payload []byte, pin string, pub *packet.PublicKey) ([]byte, error) {
	headers, body := splitPayload(payload)
	boundary := generateMIMEBoundary()
	signedPart := buildSignedPart(headers, body, boundary)

	armoredSig, err := c.Sign(signedPart, pin, pub)
	if err != nil {
		return nil, err
	}
	return buildMultipartSigned(headers, body, boundary, armoredSig), nil
}

// DecryptMIME decrypts a RFC 3156 multipart/encrypted MIME message using the
// card's on-device decryption key. The private key never leaves the hardware.
//
// payload must be a complete multipart/encrypted MIME message. key is the
// account's public key entity — its encryption subkey is used to locate the
// correct session-key packet in the ciphertext; load it with LoadEntity or
// ParseEntity.
//
// Only RSA decryption keys are supported. ECDH/Curve25519 keys require
// scalar access the card does not expose — use gpg-agent for those.
func (c *Card) DecryptMIME(payload []byte, pin string, key *pgpcrypto.Entity) ([]byte, error) {
	ciphertext, err := extractPGPCiphertext(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecrypt, err)
	}
	return c.Decrypt(ciphertext, pin, key)
}

// extractPGPCiphertext parses a multipart/encrypted MIME message (RFC 3156)
// and returns the binary OpenPGP ciphertext from the second MIME part.
// The ASCII armor is decoded so the returned bytes are a raw OpenPGP message.
func extractPGPCiphertext(payload []byte) ([]byte, error) {
	headerEnd := bytes.Index(payload, []byte("\r\n\r\n"))
	bodyOffset := 4
	if headerEnd < 0 {
		headerEnd = bytes.Index(payload, []byte("\n\n"))
		bodyOffset = 2
	}
	if headerEnd < 0 {
		return nil, fmt.Errorf("%w: no header/body separator", ErrMIME)
	}

	// Unfold RFC 2822 header continuations before parsing (handle both CRLF and LF line endings).
	unfolded := strings.ReplaceAll(string(payload[:headerEnd]), "\r\n\t", " ")
	unfolded = strings.ReplaceAll(unfolded, "\r\n ", " ")
	unfolded = strings.ReplaceAll(unfolded, "\n\t", " ")
	unfolded = strings.ReplaceAll(unfolded, "\n ", " ")

	var contentType string
	for _, line := range strings.Split(unfolded, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.ToUpper(line), "CONTENT-TYPE:") {
			contentType = strings.TrimSpace(line[len("Content-Type:"):])
			break
		}
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mediaType, "multipart/encrypted") {
		return nil, fmt.Errorf("%w: expected multipart/encrypted, got %q", ErrMIME, mediaType)
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, fmt.Errorf("%w: missing boundary parameter", ErrMIME)
	}

	mr := multipart.NewReader(bytes.NewReader(payload[headerEnd+bodyOffset:]), boundary)

	// Discard the control part (application/pgp-encrypted, "Version: 1").
	if _, err := mr.NextPart(); err != nil {
		return nil, fmt.Errorf("%w: missing control part: %w", ErrMIME, err)
	}

	// Second part holds the ASCII-armored OpenPGP message.
	dataPart, err := mr.NextPart()
	if err != nil {
		return nil, fmt.Errorf("%w: missing data part: %w", ErrMIME, err)
	}
	defer dataPart.Close()

	armoredData, err := io.ReadAll(dataPart)
	if err != nil {
		return nil, fmt.Errorf("%w: read data part: %w", ErrMIME, err)
	}

	block, err := armor.Decode(bytes.NewReader(armoredData))
	if err != nil {
		return nil, fmt.Errorf("%w: decode PGP armor: %w", ErrMIME, err)
	}
	ciphertext, err := io.ReadAll(block.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: read ciphertext: %w", ErrMIME, err)
	}
	return ciphertext, nil
}

// generateMIMEBoundary returns a random MIME boundary string.
// Falls back to a UnixNano timestamp if the random source is unavailable.
func generateMIMEBoundary() string {
	var buf [16]byte
	if n, err := randRead(buf[:]); err == nil && n == len(buf) {
		return fmt.Sprintf("----=_Part_%x", buf[:])
	}
	return fmt.Sprintf("----=_Part_%d", time.Now().UnixNano())
}

// splitPayload splits a MIME message into headers and body at the first
// CRLFCRLF sequence.
func splitPayload(payload []byte) (headers, body []byte) {
	if idx := bytes.Index(payload, []byte("\r\n\r\n")); idx >= 0 {
		return payload[:idx], payload[idx+4:]
	}
	return nil, payload
}

// buildSignedPart constructs the first MIME part content to be hashed and
// signed. This must exactly match what appears between the boundary markers
// in the output.
func buildSignedPart(headers, body []byte, _ string) []byte {
	var originalContentType []byte
	for _, line := range bytes.Split(headers, []byte("\r\n")) {
		if bytes.HasPrefix(bytes.ToUpper(line), []byte("CONTENT-TYPE:")) {
			originalContentType = line
			break
		}
	}

	var part bytes.Buffer
	if len(originalContentType) > 0 {
		part.Write(originalContentType)
		part.WriteString("\r\n\r\n")
	}
	part.Write(body)
	return part.Bytes()
}

// buildMultipartSigned assembles the complete multipart/signed MIME message.
func buildMultipartSigned(headers, body []byte, boundary string, armoredSig []byte) []byte {
	var result bytes.Buffer

	// Write transport headers, replacing Content-Type and MIME-Version.
	var originalContentType []byte
	for _, line := range bytes.Split(headers, []byte("\r\n")) {
		upper := bytes.ToUpper(line)
		if bytes.HasPrefix(upper, []byte("CONTENT-TYPE:")) {
			originalContentType = line
			continue
		}
		if bytes.HasPrefix(upper, []byte("MIME-VERSION:")) {
			continue
		}
		if len(line) > 0 {
			result.Write(line)
			result.WriteString("\r\n")
		}
	}

	result.WriteString("MIME-Version: 1.0\r\n")
	result.WriteString("Content-Type: multipart/signed; ")
	result.WriteString("boundary=\"" + boundary + "\"; ")
	result.WriteString("micalg=pgp-sha256; ")
	result.WriteString("protocol=\"application/pgp-signature\"\r\n")
	result.WriteString("\r\n")

	// First part: original body with its original Content-Type.
	result.WriteString("--" + boundary + "\r\n")
	if len(originalContentType) > 0 {
		result.Write(originalContentType)
		result.WriteString("\r\n\r\n")
	}
	result.Write(body)
	result.WriteString("\r\n")

	// Second part: detached signature.
	result.WriteString("--" + boundary + "\r\n")
	result.WriteString("Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n")
	result.WriteString("Content-Description: OpenPGP digital signature\r\n")
	result.WriteString("Content-Disposition: attachment; filename=\"signature.asc\"\r\n\r\n")
	result.Write(armoredSig)
	result.WriteString("\r\n")
	result.WriteString("--" + boundary + "--\r\n")

	return result.Bytes()
}

