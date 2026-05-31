package cardhl

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// TestParseASN1Signature_TruncatedDoesNotPanic covers the bounds-check path.
// Each input would have panicked in a naive parser with "index out of range";
// here we expect a typed error instead.
func TestParseASN1Signature_TruncatedDoesNotPanic(t *testing.T) {
	cases := []struct {
		name    string
		der     []byte
		wantErr string
	}{
		{
			name:    "R length overruns buffer",
			der:     []byte{0x30, 0x06, 0x02, 0x10, 0xAA, 0x00},
			wantErr: "R length overflow",
		},
		{
			name:    "S length overruns buffer",
			der:     []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x10, 0xAA},
			wantErr: "S length overflow",
		},
		{
			name:    "missing S after R",
			der:     []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x00},
			wantErr: "expected INTEGER tag for S",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseASN1Signature panicked: %v", r)
				}
			}()
			_, _, err := parseASN1Signature(tc.der)
			if err == nil {
				t.Fatalf("want error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestParseASN1Signature_WellFormed guards the happy path: a minimal
// SEQUENCE { INTEGER, INTEGER } must decode to the original r and s bytes.
func TestParseASN1Signature_WellFormed(t *testing.T) {
	der := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}

	r, s, err := parseASN1Signature(der)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r) != 1 || r[0] != 0x01 {
		t.Errorf("r = %x, want 01", r)
	}
	if len(s) != 1 || s[0] != 0x02 {
		t.Errorf("s = %x, want 02", s)
	}
}

func TestWriteMPI(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want []byte
	}{
		// 0x01 -> 1 significant bit.
		{"single bit", []byte{0x01}, []byte{0x00, 0x01, 0x01}},
		// 0xFF -> 8 significant bits.
		{"full byte", []byte{0xFF}, []byte{0x00, 0x08, 0xFF}},
		// Leading zeros are stripped before the bit count.
		{"leading zeros stripped", []byte{0x00, 0x00, 0x80}, []byte{0x00, 0x08, 0x80}},
		// 0x0100 -> 9 significant bits.
		{"two bytes", []byte{0x01, 0x00}, []byte{0x00, 0x09, 0x01, 0x00}},
		// All-zero input collapses to a single zero byte (0 bits).
		{"all zero", []byte{0x00, 0x00}, []byte{0x00, 0x00, 0x00}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeMPI(&buf, tc.in)
			if !bytes.Equal(buf.Bytes(), tc.want) {
				t.Fatalf("writeMPI(%x) = %x, want %x", tc.in, buf.Bytes(), tc.want)
			}
		})
	}
}

func TestWriteNewFormatLength(t *testing.T) {
	cases := []struct {
		length int
		want   []byte
	}{
		{0, []byte{0x00}},
		{191, []byte{0xBF}},
		{192, []byte{0xC0, 0x00}},
		{8383, []byte{0xDF, 0xFF}},
		{8384, []byte{0xFF, 0x00, 0x00, 0x20, 0xC0}},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		writeNewFormatLength(&buf, tc.length)
		if !bytes.Equal(buf.Bytes(), tc.want) {
			t.Errorf("writeNewFormatLength(%d) = %x, want %x", tc.length, buf.Bytes(), tc.want)
		}
	}
}

// TestArmorSignature checks that a binary packet round-trips through ASCII
// armor with the expected block type and decodes back to the same bytes.
func TestArmorSignature(t *testing.T) {
	raw := []byte{0xC2, 0x03, 0x04, 0x05, 0x06}
	out, err := armorSignature(raw)
	if err != nil {
		t.Fatalf("armorSignature: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("-----BEGIN PGP SIGNATURE-----")) {
		t.Fatalf("missing armor header: %q", out[:40])
	}

	block, err := armor.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("armor.Decode: %v", err)
	}
	if block.Type != "PGP SIGNATURE" {
		t.Errorf("block type = %q, want PGP SIGNATURE", block.Type)
	}
	got := new(bytes.Buffer)
	if _, err := got.ReadFrom(block.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(got.Bytes(), raw) {
		t.Errorf("round-trip = %x, want %x", got.Bytes(), raw)
	}
}

func TestCapitalize(t *testing.T) {
	cases := map[string]string{"": "", "sign": "Sign", "decrypt": "Decrypt", "a": "A"}
	for in, want := range cases {
		if got := capitalize(in); got != want {
			t.Errorf("capitalize(%q) = %q, want %q", in, got, want)
		}
	}
}
