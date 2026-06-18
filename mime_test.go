package cardhl

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func TestGenerateMIMEBoundaryUsesCryptoRandomBytes(t *testing.T) {
	old := randRead
	defer func() { randRead = old }()

	randRead = func(p []byte) (int, error) {
		for i := range p {
			p[i] = byte(i)
		}
		return len(p), nil
	}

	got := generateMIMEBoundary()
	want := "----=_Part_000102030405060708090a0b0c0d0e0f"
	if got != want {
		t.Fatalf("boundary = %q, want %q", got, want)
	}
}

func TestGenerateMIMEBoundaryFallsBackToUnixNano(t *testing.T) {
	old := randRead
	defer func() { randRead = old }()

	randRead = func(_ []byte) (int, error) {
		return 0, errors.New("random source unavailable")
	}

	const prefix = "----=_Part_"
	got := generateMIMEBoundary()
	if !strings.HasPrefix(got, prefix) {
		t.Fatalf("boundary = %q, want prefix %q", got, prefix)
	}
	if _, err := strconv.ParseInt(strings.TrimPrefix(got, prefix), 10, 64); err != nil {
		t.Fatalf("fallback boundary suffix is not a UnixNano timestamp: %v", err)
	}
}

func TestExtractPGPCiphertext(t *testing.T) {
	const boundary = "test-boundary-42"
	const fakePlain = "binary ciphertext data"

	// Wrap the fake payload in ASCII armor.
	var armorBuf bytes.Buffer
	aw, err := armor.Encode(&armorBuf, "PGP MESSAGE", nil)
	if err != nil {
		t.Fatalf("armor.Encode: %v", err)
	}
	if _, err := aw.Write([]byte(fakePlain)); err != nil {
		t.Fatalf("armor write: %v", err)
	}
	if err := aw.Close(); err != nil {
		t.Fatalf("armor close: %v", err)
	}

	// Build a synthetic multipart/encrypted MIME message.
	var msg bytes.Buffer
	msg.WriteString("Content-Type: multipart/encrypted; boundary=\"" + boundary +
		"\"; protocol=\"application/pgp-encrypted\"\r\n")
	msg.WriteString("MIME-Version: 1.0\r\n\r\n")
	msg.WriteString("--" + boundary + "\r\n")
	msg.WriteString("Content-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n")
	msg.WriteString("\r\n--" + boundary + "\r\n")
	msg.WriteString("Content-Type: application/octet-stream\r\n\r\n")
	msg.Write(armorBuf.Bytes())
	msg.WriteString("\r\n--" + boundary + "--\r\n")

	got, err := extractPGPCiphertext(msg.Bytes())
	if err != nil {
		t.Fatalf("extractPGPCiphertext: %v", err)
	}
	if string(got) != fakePlain {
		t.Errorf("got %q, want %q", got, fakePlain)
	}
}

func TestExtractPGPCiphertextWrongMediaType(t *testing.T) {
	payload := []byte("Content-Type: text/plain\r\n\r\nHello")
	_, err := extractPGPCiphertext(payload)
	if err == nil {
		t.Fatal("expected error for non-multipart/encrypted payload, got nil")
	}
	if !errors.Is(err, ErrMIME) {
		t.Errorf("error = %v, want to wrap ErrMIME", err)
	}
}

func TestExtractPGPCiphertextNoSeparator(t *testing.T) {
	_, err := extractPGPCiphertext([]byte("no-crlf-crlf-here"))
	if !errors.Is(err, ErrMIME) {
		t.Errorf("error = %v, want ErrMIME", err)
	}
}

func TestBuildMultipartSignedStructure(t *testing.T) {
	headers := []byte("From: alice@example.com\r\nContent-Type: text/plain")
	body := []byte("Hello world")
	boundary := "test-boundary"
	sig := []byte("-----BEGIN PGP SIGNATURE-----\nfakesig\n-----END PGP SIGNATURE-----\n")

	out := buildMultipartSigned(headers, body, boundary, sig)
	s := string(out)

	if !strings.Contains(s, "multipart/signed") {
		t.Error("missing multipart/signed Content-Type")
	}
	if !strings.Contains(s, `boundary="`+boundary+`"`) {
		t.Error("missing boundary parameter")
	}
	if !strings.Contains(s, "micalg=pgp-sha256") {
		t.Error("missing micalg parameter")
	}
	if !strings.Contains(s, `protocol="application/pgp-signature"`) {
		t.Error("missing protocol parameter")
	}
	if !strings.Contains(s, "application/pgp-signature") {
		t.Error("missing signature part Content-Type")
	}
	if !strings.Contains(s, "Hello world") {
		t.Error("missing original body in output")
	}
	if !strings.Contains(s, "BEGIN PGP SIGNATURE") {
		t.Error("missing PGP signature in output")
	}
	// Transport header must appear, Content-Type of inner part must not appear at top level.
	if !strings.Contains(s, "From: alice@example.com") {
		t.Error("missing From transport header")
	}
}
