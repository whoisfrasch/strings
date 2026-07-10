package diff

import (
	"testing"

	"github.com/whoisfrasch/strings/internal"
)

func TestCompareIdentical(t *testing.T) {
	a := []internal.StringResult{
		{Value: "hello"},
		{Value: "world"},
	}
	b := []internal.StringResult{
		{Value: "hello"},
		{Value: "world"},
	}
	result := Compare(a, b)
	if result.Common != 2 {
		t.Errorf("Common = %d, want 2", result.Common)
	}
	if len(result.OnlyA) != 0 {
		t.Errorf("OnlyA = %v, want empty", result.OnlyA)
	}
	if len(result.OnlyB) != 0 {
		t.Errorf("OnlyB = %v, want empty", result.OnlyB)
	}
}

func TestCompareDisjoint(t *testing.T) {
	a := []internal.StringResult{
		{Value: "hello"},
	}
	b := []internal.StringResult{
		{Value: "world"},
	}
	result := Compare(a, b)
	if result.Common != 0 {
		t.Errorf("Common = %d, want 0", result.Common)
	}
	if len(result.OnlyA) != 1 || result.OnlyA[0] != "hello" {
		t.Errorf("OnlyA = %v, want [hello]", result.OnlyA)
	}
	if len(result.OnlyB) != 1 || result.OnlyB[0] != "world" {
		t.Errorf("OnlyB = %v, want [world]", result.OnlyB)
	}
}

func TestComparePartialOverlap(t *testing.T) {
	a := []internal.StringResult{
		{Value: "shared"},
		{Value: "onlyInA"},
	}
	b := []internal.StringResult{
		{Value: "shared"},
		{Value: "onlyInB"},
	}
	result := Compare(a, b)
	if result.Common != 1 {
		t.Errorf("Common = %d, want 1", result.Common)
	}
	if len(result.OnlyA) != 1 || result.OnlyA[0] != "onlyInA" {
		t.Errorf("OnlyA = %v, want [onlyInA]", result.OnlyA)
	}
	if len(result.OnlyB) != 1 || result.OnlyB[0] != "onlyInB" {
		t.Errorf("OnlyB = %v, want [onlyInB]", result.OnlyB)
	}
}

func TestCompareEmpty(t *testing.T) {
	result := Compare(nil, nil)
	if result.Common != 0 {
		t.Errorf("Common = %d, want 0", result.Common)
	}
	if len(result.OnlyA) != 0 {
		t.Errorf("OnlyA = %v, want empty", result.OnlyA)
	}
	if len(result.OnlyB) != 0 {
		t.Errorf("OnlyB = %v, want empty", result.OnlyB)
	}
}

func TestCompareDuplicateValues(t *testing.T) {
	a := []internal.StringResult{
		{Value: "dup"},
		{Value: "dup"},
		{Value: "unique"},
	}
	b := []internal.StringResult{
		{Value: "dup"},
	}
	result := Compare(a, b)
	if result.Common != 1 {
		t.Errorf("Common = %d, want 1", result.Common)
	}
	if len(result.OnlyA) != 1 || result.OnlyA[0] != "unique" {
		t.Errorf("OnlyA = %v, want [unique]", result.OnlyA)
	}
}

func TestCompareSorted(t *testing.T) {
	a := []internal.StringResult{
		{Value: "zebra"},
		{Value: "apple"},
	}
	b := []internal.StringResult{}
	result := Compare(a, b)
	if len(result.OnlyA) != 2 {
		t.Fatalf("OnlyA has %d items, want 2", len(result.OnlyA))
	}
	if result.OnlyA[0] != "apple" || result.OnlyA[1] != "zebra" {
		t.Errorf("OnlyA not sorted: %v", result.OnlyA)
	}
}
