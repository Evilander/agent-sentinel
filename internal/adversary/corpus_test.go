package adversary

import "testing"

func TestExpandedCorpus_MultipliesCases(t *testing.T) {
	base := DefaultCorpus()
	out := ExpandedCorpus(base, 3)
	expected := len(base) * 3
	if len(out) != expected {
		t.Fatalf("expected %d cases, got %d", expected, len(out))
	}
}
