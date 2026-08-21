//go:build !unix

package app

// oNoFollow is nothing where O_NOFOLLOW does not exist (Windows). The guard it
// backs -- a key file or the inventory must be the file that was named, not a
// link to another -- is absent there; the CLI compiles for Windows so the tree
// stays portable, and komizo's operators and boxes are unix. Stated here
// rather than hidden in a shared flag expression.
const oNoFollow = 0
