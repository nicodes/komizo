//go:build !linux

package rollout

import "errors"

func availableCapacity(string) (uint64, uint64, error) {
	return 0, 0, errors.New("Docker rollout capacity is supported only on Linux")
}
