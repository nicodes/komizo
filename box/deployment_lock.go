package box

import (
	"context"
)

// LockDeployment shares the deploy script's order: app, then host. The worker
// runs in rootd, so client termination cannot release these locks mid-effect.
func LockDeployment(ctx context.Context, root, app string) (func(), error) {
	if _, err := appStatePath(root, app); err != nil {
		return nil, err
	}
	appUnlock, err := lockHostFile(ctx, root, "deploy-"+app+".lock")
	if err != nil {
		return nil, err
	}
	hostUnlock, err := lockHostFile(ctx, root, "operation.lock")
	if err != nil {
		appUnlock()
		return nil, err
	}
	return func() { hostUnlock(); appUnlock() }, nil
}
