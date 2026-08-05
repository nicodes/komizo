package app

import (
	"strings"

	"github.com/nicodes/komizo/box"
)

// The devices a box will take orders from, as the CLI carries them.
//
// komizo-be design/app-only.md §4 and §6: the app signs its commands and the
// box verifies them against keys planted with root. The service never chooses
// what is in that list, and this flag is why -- the operator copies a key from
// the app and passes it to the machine, so the only thing that ever decided
// which devices a box trusts is a person who could already do anything to it.
//
// A public key, so nothing here is secret. What it is, is AUTHORITY, which is
// why it is validated in both places rather than trusted from one.

// deviceKeys collects a repeatable --device-key.
type deviceKeys []string

func (d *deviceKeys) String() string { return strings.Join(*d, ",") }

// Set validates as it goes, so an error names the value that is wrong.
//
// These are copied between two windows, which is where a truncated base64
// string comes from -- and a truncated authority that failed later, on the box,
// would fail after the SSH connection and in the middle of somebody's setup.
func (d *deviceKeys) Set(v string) error {
	v = strings.TrimSpace(v)
	if _, err := box.ParseDeviceKey(v); err != nil {
		return err
	}
	for _, seen := range *d {
		if seen == v {
			// The same key twice is somebody pasting twice, and the result they
			// wanted is the result they get.
			return nil
		}
	}
	*d = append(*d, v)
	return nil
}

const deviceKeyUsage = "a device that may command this box, from the app (repeatable)"
