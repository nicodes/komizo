package box

import (
	"context"
	"testing"
	"time"
)

func TestHeavyHostOperationIsExclusiveAndNestedCleanupDoesNotDeadlock(t *testing.T) {
	root := t.TempDir()
	ctx, release, err := previewOperation(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	_, nested, err := previewOperation(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	nested()
	blocked, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, _, err := previewOperation(blocked, root); err == nil {
		t.Fatal("two heavy operations admitted")
	}
}
