package box

import (
	"encoding/json"
	"testing"
)

func TestDiskAvailableIsBavailNotBfree(t *testing.T) {
	const bsize, blocks, bfree, bavail uint64 = 4096, 1000, 400, 250
	used, size, avail := diskAccounting(bsize, blocks, bfree, bavail)
	rawFree := bfree * bsize
	if avail == rawFree {
		t.Fatal("Bavail equals Bfree in this fixture, so the test cannot tell them apart")
	}
	if avail != bavail*bsize {
		t.Errorf("available = %d, want Bavail*Bsize = %d", avail, bavail*bsize)
	}
	if used != (blocks-bfree)*bsize {
		t.Errorf("used = %d, want (Blocks-Bfree)*Bsize = %d", used, (blocks-bfree)*bsize)
	}
	if size != used+avail {
		t.Errorf("size = %d, want used+available = %d", size, used+avail)
	}
	if size == blocks*bsize {
		t.Error("size should not be raw Blocks*Bsize when Bfree != Bavail")
	}
}

func TestMemAndDiskJSONIncludeAvailable(t *testing.T) {
	mb, err := json.Marshal(Mem{Total: 10, Used: 6, Available: 4})
	if err != nil {
		t.Fatal(err)
	}
	var mem map[string]json.Number
	if err := json.Unmarshal(mb, &mem); err != nil {
		t.Fatal(err)
	}
	if _, ok := mem["available"]; !ok {
		t.Fatalf("mem JSON missing available: %s", mb)
	}
	if mem["available"].String() != "4" {
		t.Errorf("mem available = %s, want 4", mem["available"])
	}

	zb, err := json.Marshal(Mem{})
	if err != nil {
		t.Fatal(err)
	}
	var zero map[string]json.RawMessage
	if err := json.Unmarshal(zb, &zero); err != nil {
		t.Fatal(err)
	}
	if _, ok := zero["available"]; !ok {
		t.Fatalf("zero Mem JSON omitted available: %s", zb)
	}

	db, err := json.Marshal(Disk{Mount: "/", Used: 8, Size: 10, Available: 2})
	if err != nil {
		t.Fatal(err)
	}
	var disk map[string]any
	if err := json.Unmarshal(db, &disk); err != nil {
		t.Fatal(err)
	}
	if _, ok := disk["available"]; !ok {
		t.Fatalf("disk JSON missing available: %s", db)
	}
	if disk["available"].(float64) != 2 {
		t.Errorf("disk available = %v, want 2", disk["available"])
	}
}
