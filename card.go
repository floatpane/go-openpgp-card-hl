package cardhl

import (
	"fmt"
	"strings"

	"github.com/ebfe/scard"

	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/drivers/pcsc"
	"cunicu.li/go-iso7816/filter"

	openpgp "cunicu.li/go-openpgp-card"
)

// Card is a connected OpenPGP smartcard session. It is not safe for concurrent
// use; serialize calls or open one Card per goroutine. Always Close it.
type Card struct {
	pgp *openpgp.Card
	ctx *scard.Context
}

// Open connects to the first available OpenPGP smartcard via PC/SC.
//
// Errors are actionable: a missing daemon yields ErrNoPCSC, an absent card
// yields ErrNoCard, and an applet that will not initialize yields ErrCardInit.
func Open() (*Card, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %w\n"+
				"Make sure the PC/SC daemon is running:\n"+
				"  sudo systemctl enable --now pcscd.socket\n"+
				"You may also need the ccid package for USB smartcard support",
			ErrNoPCSC, err,
		)
	}

	pcscCard, err := pcsc.OpenFirstCard(ctx, filter.HasApplet(iso.AidOpenPGP), true)
	if err != nil {
		_ = ctx.Release()
		return nil, fmt.Errorf(
			"%w: %w\n"+
				"Make sure your card (e.g. YubiKey) is plugged in and has an OpenPGP key configured",
			ErrNoCard, err,
		)
	}

	isoCard := iso.NewCard(pcscCard)
	pgpCard, err := openpgp.NewCard(isoCard)
	if err != nil {
		_ = pcscCard.Close()
		_ = ctx.Release()
		return nil, fmt.Errorf("%w: %w", ErrCardInit, err)
	}

	return &Card{pgp: pgpCard, ctx: ctx}, nil
}

// Close releases the card handle and the underlying PC/SC context.
func (c *Card) Close() error {
	err := c.pgp.Close()
	if c.ctx != nil {
		if rerr := c.ctx.Release(); err == nil {
			err = rerr
		}
	}
	return err
}

// OpenPGP exposes the underlying go-openpgp-card handle for advanced use
// (cardholder data, key generation, PIN management). Most callers do not need
// it; the high-level Sign, Decrypt, and Info cover the common path.
func (c *Card) OpenPGP() *openpgp.Card { return c.pgp }

// KeyInfo describes one key slot on the card.
type KeyInfo struct {
	Slot        string // "sign", "decrypt", or "auth"
	Algorithm   string // e.g. "ed25519", "rsa2048", "nistp256"
	Status      string // "generated", "imported", or "absent"
	Fingerprint string // hex, uppercase; empty if absent
}

// Info is human-readable metadata about a connected card.
type Info struct {
	Manufacturer string
	Serial       string // hex
	Version      string
	Cardholder   string // empty if unset
	Keys         []KeyInfo
}

var slotNames = []struct {
	ref  openpgp.KeyRef
	name string
}{
	{openpgp.KeySign, "sign"},
	{openpgp.KeyDecrypt, "decrypt"},
	{openpgp.KeyAuthn, "auth"},
}

// Info returns structured metadata about the card and its key slots.
func (c *Card) Info() (*Info, error) {
	aid := c.pgp.AID
	info := &Info{
		Manufacturer: aid.Manufacturer.String(),
		Serial:       fmt.Sprintf("%X", aid.Serial),
		Version:      aid.Version.String(),
		Keys:         c.ListKeys(),
	}

	if ch, err := c.pgp.GetCardholder(); err == nil && ch.Name != "" {
		info.Cardholder = ch.Name
	}

	return info, nil
}

// ListKeys returns the sign, decrypt, and auth slots and their state.
func (c *Card) ListKeys() []KeyInfo {
	out := make([]KeyInfo, 0, len(slotNames))
	for _, s := range slotNames {
		ki, ok := c.pgp.Keys[s.ref]
		k := KeyInfo{Slot: s.name, Status: "absent"}
		if ok {
			k.Algorithm = ki.AlgAttrs.String()
			k.Status = keyStatusString(ki.Status)
			if len(ki.Fingerprint) > 0 && k.Status != "absent" {
				k.Fingerprint = fmt.Sprintf("%X", ki.Fingerprint)
			}
		}
		out = append(out, k)
	}
	return out
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func keyStatusString(s openpgp.KeyStatus) string {
	switch s {
	case openpgp.KeyGenerated:
		return "generated"
	case openpgp.KeyImported:
		return "imported"
	case openpgp.KeyNotPresent:
		return "absent"
	default:
		return "absent"
	}
}

// String renders Info as the kind of block a CLI would print.
func (i *Info) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Manufacturer: %s\n", i.Manufacturer)
	fmt.Fprintf(&b, "Serial:       %s\n", i.Serial)
	fmt.Fprintf(&b, "Version:      %s\n", i.Version)
	if i.Cardholder != "" {
		fmt.Fprintf(&b, "Cardholder:   %s\n", i.Cardholder)
	}
	for _, k := range i.Keys {
		fmt.Fprintf(&b, "%-8s Key:  %s (%s)", capitalize(k.Slot), k.Algorithm, k.Status)
		if k.Fingerprint != "" {
			fmt.Fprintf(&b, " %s", k.Fingerprint)
		}
		b.WriteString("\n")
	}
	return b.String()
}
