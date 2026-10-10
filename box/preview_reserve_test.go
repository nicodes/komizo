package box

import "testing"

func TestProductionReserveUsesPhysicalMemoryAndIncludesDatabase(t *testing.T) {
	k, note := ParsePreviewKnob("PRODUCTION_RESERVE=512m\nDB_MEM_LIMIT=128m\nMEM_BUDGET=256m")
	if note != "" {
		t.Fatal(note)
	}
	report := []byte(`{"system":{"mem":{"total":1006395392,"available":9999999999}}}`)
	if err := previewProductionReserve(k, report); err != nil {
		t.Fatal(err)
	}
	k.MemoryBudget = 512 << 20
	if err := previewProductionReserve(k, report); err == nil {
		t.Fatal("preview oversubscription accepted")
	}
	if err := previewProductionReserve(k, nil); err == nil {
		t.Fatal("unknown RAM accepted")
	}
	k, note = ParsePreviewKnob("PRODUCTION_RESERVE=bad\nDB_MEM_LIMIT=0")
	if !k.InvalidBudget || note == "" {
		t.Fatal("invalid reserves did not fail closed")
	}
}
