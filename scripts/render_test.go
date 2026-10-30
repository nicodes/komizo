package scripts

import "testing"

func TestOpaquePlaceholderShapedValuesRemainData(t *testing.T) {
	if got := render("hello __VALUE__", "__VALUE__", "__BC__"); got != "hello __BC__" {
		t.Fatalf("placeholder-shaped value changed: %q", got)
	}
}

func TestAForgottenPlaceholderStillPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("unsubstituted placeholder rendered quietly")
		}
	}()
	render("hello __NOBODY_PASSED_THIS__", "__X__", "y")
}
