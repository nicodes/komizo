package main

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
	var order []candidate
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		order = append(order, candidate{"wl-copy", nil})
	}
	order = append(order,
		candidate{"pbcopy", nil},                                // macOS
		candidate{"xclip", []string{"-selection", "clipboard"}}, // X11
		candidate{"xsel", []string{"--clipboard", "--input"}},   // X11
		candidate{"wl-copy", nil},                               // Wayland, if the env var was unset
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

// copyToClipboard sends the file's contents to the clipboard without them
// passing through this process's output.
func copyToClipboard(path string) error {
	argv := clipboardCmd()
	if argv == nil {
		return fmt.Errorf("no clipboard tool found (looked for wl-copy, pbcopy, xclip, xsel, clip.exe)")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not read %s: %w", path, err)
	}
	c := exec.Command(argv[0], argv[1:]...)
	c.Stdin = strings.NewReader(string(data))
	// Never surface the tool's own output: wl-copy is silent, but xclip has been
	// known to echo, and this is the one buffer that must not reach the screen.
	c.Stdout, c.Stderr = nil, nil
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s failed", argv[0])
	}
	return nil
}
