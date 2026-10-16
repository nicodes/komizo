package app

import (
	"os"

	"github.com/nicodes/komizo/scripts"
)

// These helpers finish all their work synchronously before os.Exit. Keep the
// race detector enabled, but do not pay its one-second exit sleep for every
// fixture command. The parent test process retains its normal race settings.
func testProcessScript(testName, marker string) string {
	return "#!/bin/sh\n" + marker + "=1\nexport " + marker + "\n" +
		"GORACE=\"${GORACE:-} atexit_sleep_ms=0\"\nexport GORACE\n" +
		"exec " + scripts.ShQuote(os.Args[0]) + " -test.run=" +
		scripts.ShQuote("^"+testName+"$") + " -- \"$@\"\n"
}
