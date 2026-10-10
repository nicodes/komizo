package workload

import (
	"crypto/sha256"
	"fmt"
)

func IsolatedIngress(app string) string {
	if len(app) > 40 {
		digest := sha256.Sum256([]byte(app))
		app = app[:40] + fmt.Sprintf("-%x", digest)[:7]
	}
	return "komizo-" + app + "-ingress"
}
