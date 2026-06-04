package history

import (
	"testing"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	r := &types.SystemReport{
		Hostname:  "h1",
		Timestamp: "2026-06-04T00:00:00Z",
		HealthAnalysis: &types.HealthAnalysisResult{
			FailedUnits: []types.UnitHealthInfo{{Name: "x.service"}},
		},
	}
	if err := Save(r, dir, 50); err != nil {
		t.Fatal(err)
	}
	got := Load(dir, 0)
	if len(got) != 1 || got[0].Hostname != "h1" {
		t.Fatalf("round-trip failed: %+v", got)
	}
	if got[0].HealthAnalysis == nil || len(got[0].HealthAnalysis.FailedUnits) != 1 {
		t.Fatal("nested health analysis lost in round-trip")
	}
}

func TestRetentionKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		if err := Save(&types.SystemReport{Hostname: "h", Timestamp: "2026-06-04T00:00:00Z"}, dir, 2); err != nil {
			t.Fatal(err)
		}
	}
	if got := Load(dir, 0); len(got) != 2 {
		t.Fatalf("retention: kept %d files, want 2", len(got))
	}
}
