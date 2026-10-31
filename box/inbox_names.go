package box

import "strings"

// Rootd ignores the API's private atomic-write temporaries. This is the
// existing on-disk inbox protocol shared with the Rust API.
const TempPrefix = ".tmp-"

func IsTemporary(name string) bool { return strings.HasPrefix(name, TempPrefix) }
