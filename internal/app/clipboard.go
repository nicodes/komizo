package app

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Copying the deploy key to the clipboard, so the private half never has to be
// printed to reach GitHub.
//
// The result screen shows the key's PATH and not its contents, deliberately:
// that screen is exactly the sort of thing that ends up in a screenshot or a
// scrollback buffer someone else reads. But a path alone means opening another
// terminal, running cat, and selecting a multi-line PEM by hand -- so komizo
// puts it on the clipboard instead. Same property, none of the work.

// clipboardCmd returns the command that reads stdin onto the clipboard, or nil.
// Ordered by session type first: on Wayland, xclip may be installed and present
// an X11 clipboard that the compositor's applications do not read.
func clipboardCmd() []string {
	type candidate struct {
		bin  string
		args []string
	}
	// --type text/plain on wl-copy is load-bearing, not tidiness. wl-copy sniffs
	// the content and advertises a type to match, and it recognises a private
	// key: it offers ONLY application/x-pem-file. Every text field asks for
	// text/plain, finds no such offer, and pastes nothing -- silently, because
	// the copy itself succeeded. The host keys are plain text and were never
	// affected, which is what made this look like a bug in one value and not
	// the other.
	//
	// The X11 tools do not sniff: they offer STRING/UTF8_STRING regardless, so
	// they are left alone.
	wlArgs := []string{"--type", "text/plain"}
	var order []candidate
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		order = append(order, candidate{"wl-copy", wlArgs})
	}
	order = append(order,
		candidate{"pbcopy", nil},                                // macOS
		candidate{"xclip", []string{"-selection", "clipboard"}}, // X11
		candidate{"xsel", []string{"--clipboard", "--input"}},   // X11
		candidate{"wl-copy", wlArgs},                            // Wayland, if the env var was unset
		candidate{"clip.exe", nil},                              // WSL
	)
	for _, c := range order {
		if p, err := exec.LookPath(c.bin); err == nil {
			return append([]string{p}, c.args...)
		}
	}
	return nil
}

func clipboardAvailable() bool { return clipboardCmd() != nil }

// clipboardText is what actually goes on the clipboard: the value with any
// trailing newlines taken off.
func clipboardText(s string) string { return strings.TrimRight(s, "\n") }

// copyToClipboard puts text on the clipboard.
//
// A variable so a test can drive the copy path on a machine that has no
// clipboard tool. Every CI runner is such a machine, and skipping there would
// leave this untested in exactly the place nobody runs it by hand.
var copyToClipboard = copyToSystemClipboard

// copyToSystemClipboard is the real thing: text on the clipboard, without a
// trailing newline.
//
// Trimmed here rather than at each call site, so no future copy can put one
// back. Everything this tool copies is pasted into a text field in a browser,
// where a trailing newline is a blank last line that gets saved as part of the
// value -- and the deploy action writes both values out with printf '%s\n',
// which puts exactly one back where a file wants one.
//
// That includes the private key. The newline after -----END OPENSSH PRIVATE
// KEY----- is the PEM terminator and the FILE needs it; the GitHub secret does
// not, because the action supplies it on the way out.
func copyToSystemClipboard(text string) error {
	text = clipboardText(text)
	argv := clipboardCmd()
	if argv == nil {
		return fmt.Errorf("no clipboard tool found (looked for wl-copy, pbcopy, xclip, xsel, clip.exe)")
	}
	c := exec.Command(argv[0], argv[1:]...)
	c.Stdin = strings.NewReader(text)
	// The helper forks a child that serves the selection; without this it dies
	// with us and the paste comes back empty.
	detach(c)
	// Never surface the tool's own output: wl-copy is silent, but xclip has been
	// known to echo, and this is the one buffer that must not reach the screen.
	c.Stdout, c.Stderr = nil, nil
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s failed", argv[0])
	}
	return nil
}
