package box

import (
	"testing"
	"time"
)

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

func TestPreviewCapacityRejectsStaleMissingAndFutureObservations(t *testing.T) {
	now := time.Now().UTC()
	for _, body := range []string{`{}`, `{"at":"2000-01-01T00:00:00Z"}`, `{"at":"2099-01-01T00:00:00Z"}`, `bad`} {
		if previewReportFresh([]byte(body), now) == nil {
			t.Fatalf("accepted unavailable observation: %s", body)
		}
	}
	if err := previewReportFresh([]byte(`{"at":"`+now.Format(time.RFC3339)+`"}`), now); err != nil {
		t.Fatal(err)
	}
}
