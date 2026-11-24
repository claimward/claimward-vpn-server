package pf

import "testing"

func TestReferencedTablesKeepsOnlyWhatARuleNames(t *testing.T) {
	p := Plan{
		Tables: []Table{{Name: "a"}, {Name: "b"}, {Name: "c"}},
		Rules:  []Spec{{SrcTable: "c"}, {}, {SrcTable: "a"}, {SrcTable: "c"}},
	}
	got := p.referencedTables()
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "c" {
		t.Fatalf("referencedTables = %+v, want a then c", got)
	}
	if n := len((Plan{Tables: p.Tables}).referencedTables()); n != 0 {
		t.Fatalf("with no rule, %d tables kept", n)
	}
}
