package extractors

import "testing"

func TestRegistry(t *testing.T) {
	for _, name := range []string{"criminalip", "feodotracker", "viribacktracker"} {
		if nil == Registry[name] {
			t.Errorf("Registry[%q] is not registered", name)
		}
	}
}

func TestAPIRegistry(t *testing.T) {
	if nil == APIRegistry["threatfox"] {
		t.Error(`APIRegistry["threatfox"] is not registered`)
	}
}

func TestRegistriesDoNotOverlap(t *testing.T) {
	for name := range APIRegistry {
		if _, ok := Registry[name]; ok {
			t.Errorf("%q is registered as both a body and an API extractor", name)
		}
	}
}
