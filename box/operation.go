package box

import "context"

type operationKey struct{}

// Nested eviction/cleanup participates in its caller's already held operation.
func previewOperation(ctx context.Context, root string) (context.Context, func(), error) {
	if owned, ok := ctx.Value(operationKey{}).(string); ok && owned == root {
		return ctx, func() {}, nil
	}
	release, err := lockHostFile(ctx, root, "operation.lock")
	if err != nil {
		return ctx, nil, err
	}
	return context.WithValue(ctx, operationKey{}, root), release, nil
}
