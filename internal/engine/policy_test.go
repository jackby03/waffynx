package engine

import (
	"strings"
	"sync"
	"testing"
)

func TestPolicyStoreAddAssignsIDWhenMissing(t *testing.T) {
	ps := NewPolicyStore()

	if err := ps.Add(&Policy{Name: "no-id"}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	list := ps.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(list))
	}
	if list[0].ID == "" {
		t.Error("expected Add to assign an ID when the policy had none")
	}
}

func TestPolicyStoreAddRejectsDuplicateID(t *testing.T) {
	ps := NewPolicyStore()

	if err := ps.Add(&Policy{ID: "p1", Name: "first"}); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	err := ps.Add(&Policy{ID: "p1", Name: "second"})
	if err == nil {
		t.Fatal("expected a duplicate ID to be rejected")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected an 'already exists' error, got %v", err)
	}

	// The original must survive the rejected write.
	got, getErr := ps.Get("p1")
	if getErr != nil {
		t.Fatalf("Get after rejected Add: %v", getErr)
	}
	if got.Name != "first" {
		t.Errorf("rejected Add must not overwrite: got name %q", got.Name)
	}
}

func TestPolicyStoreGetMissing(t *testing.T) {
	ps := NewPolicyStore()
	if _, err := ps.Get("nope"); err == nil {
		t.Fatal("expected an error for an unknown policy")
	}
}

func TestPolicyStoreRemove(t *testing.T) {
	ps := NewPolicyStore()
	for _, id := range []string{"a", "b", "c"} {
		if err := ps.Add(&Policy{ID: id}); err != nil {
			t.Fatalf("Add(%s): %v", id, err)
		}
	}

	if err := ps.Remove("b"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	list := ps.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 policies after removal, got %d", len(list))
	}
	// Order must be preserved, with the removed entry gone.
	if list[0].ID != "a" || list[1].ID != "c" {
		t.Errorf("expected order [a c], got [%s %s]", list[0].ID, list[1].ID)
	}

	if err := ps.Remove("b"); err == nil {
		t.Fatal("expected removing an unknown policy to fail")
	}
}

// TestPolicyStoreListIsOrderedAndCopy guards the two properties callers rely on:
// insertion order, and a snapshot the caller may mutate freely.
func TestPolicyStoreListIsOrderedAndCopy(t *testing.T) {
	ps := NewPolicyStore()
	for _, id := range []string{"z", "a", "m"} {
		if err := ps.Add(&Policy{ID: id, Name: id}); err != nil {
			t.Fatalf("Add(%s): %v", id, err)
		}
	}

	list := ps.List()
	if len(list) != 3 || list[0].ID != "z" || list[1].ID != "a" || list[2].ID != "m" {
		t.Fatalf("expected insertion order [z a m], got %v", []string{list[0].ID, list[1].ID, list[2].ID})
	}

	// Mutating the returned slice must not corrupt the store.
	list[0] = nil
	if again := ps.List(); again[0] == nil {
		t.Error("List returned a slice sharing backing storage with the store")
	}
}

// TestPolicyStoreConcurrentAccess runs under -race in CI: the store is read by
// the data plane and written by the control plane.
func TestPolicyStoreConcurrentAccess(t *testing.T) {
	ps := NewPolicyStore()
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := string(rune('a' + n%26))
			_ = ps.Add(&Policy{ID: id})
			_, _ = ps.Get(id)
			_ = ps.List()
			_ = ps.Remove(id)
		}(i)
	}
	wg.Wait()
}
