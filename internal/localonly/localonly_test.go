package localonly

import (
	"errors"
	"testing"
)

func TestSuggest(t *testing.T) {
	cases := []struct {
		class Class
		name  string
		want  bool
	}{
		{ClassDev, "JWT_SECRET", true},
		{ClassTest, "session_secret", true},
		{ClassDev, "APP_SIGNING_KEY", true},
		{ClassDev, "DB_ENCRYPTION_KEY", true},
		{ClassDev, "SECRET_KEY_BASE", true},
		{ClassDev, "API_KEY", false},
		{ClassDev, "SECRET", false},
		{ClassProd, "JWT_SECRET", false},
		{"", "JWT_SECRET", false},
	}
	for _, c := range cases {
		_, got := Suggest(c.class, c.name)
		if got != c.want {
			t.Errorf("Suggest(%q, %q) = %v, want %v", c.class, c.name, got, c.want)
		}
	}
}

func TestCheckConnection(t *testing.T) {
	if err := CheckConnection(ClassProd, Ephemeral); !errors.Is(err, ErrEphemeralClass) {
		t.Fatalf("prod ephemeral: %v", err)
	}
	if err := CheckConnection("", Ephemeral); !errors.Is(err, ErrEphemeralClass) {
		t.Fatalf("unclassified ephemeral: %v", err)
	}
	if err := CheckConnection(ClassDev, Ephemeral); err != nil {
		t.Fatal(err)
	}
	if err := CheckConnection(ClassProd, Operation); err != nil {
		t.Fatal(err)
	}
}

func TestCheckRunRefusesUnimplemented(t *testing.T) {
	for _, m := range []Mode{Operation, Contained} {
		if err := CheckRun(ClassDev, m); !errors.Is(err, ErrNotAvailable) {
			t.Errorf("%s: %v", m, err)
		}
	}
	if err := CheckRun(ClassDev, Ephemeral); err != nil {
		t.Fatal(err)
	}
}

func TestWeakens(t *testing.T) {
	if !Weakens(Ephemeral, Contained) || !Weakens(Operation, "") || !Weakens(Ephemeral, Operation) {
		t.Fatal("expected weakening")
	}
	if Weakens("", Ephemeral) || Weakens(Contained, Operation) || Weakens(Ephemeral, Ephemeral) {
		t.Fatal("unexpected weakening")
	}
}

func TestParse(t *testing.T) {
	if _, err := ParseMode("nope"); !errors.Is(err, ErrInvalidMode) {
		t.Fatal(err)
	}
	if _, err := ParseClass("staging"); !errors.Is(err, ErrInvalidClass) {
		t.Fatal(err)
	}
}

func TestGenerateShapes(t *testing.T) {
	v, err := Generate(Shape{})
	if err != nil || len(v) != 64 {
		t.Fatalf("default: %q %v", v, err)
	}
	v, err = Generate(Shape{Length: 20, Alphabet: "ab"})
	if err != nil || len(v) != 20 {
		t.Fatalf("alphabet: %q %v", v, err)
	}
	for _, r := range v {
		if r != 'a' && r != 'b' {
			t.Fatalf("outside alphabet: %q", v)
		}
	}
	if _, err := Generate(Shape{Length: maxLength + 1}); err == nil {
		t.Fatal("expected range error")
	}
	a, _ := Generate(Shape{})
	b, _ := Generate(Shape{})
	if a == b {
		t.Fatal("values must differ")
	}
}

func TestSessionStable(t *testing.T) {
	s := NewSession()
	a, _ := s.Value("JWT_SECRET", Shape{})
	b, _ := s.Value("JWT_SECRET", Shape{})
	c, _ := s.Value("SESSION_SECRET", Shape{})
	if a != b || a == c {
		t.Fatal("session values must be stable per field and distinct across fields")
	}
	if d, _ := NewSession().Value("JWT_SECRET", Shape{}); d == a {
		t.Fatal("sessions must differ")
	}
}
