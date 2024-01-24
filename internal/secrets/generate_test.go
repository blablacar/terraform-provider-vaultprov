package secrets

import (
	"math/rand"
	"reflect"
	"testing"
)

func TestRandomSecretLength(t *testing.T) {
	for i := 0; i < 10; i++ {
		l := rand.Intn(2048)

		secret, err := GenerateRandomSecret(l)
		if err != nil {
			t.Fatal("error:", err)
		}

		if len(secret) != l {
			t.Fatalf("Wrong secret's lenght: %d. Expected: %d", len(secret), l)
		}
	}
}

func TestRandomSecretUniqueness(t *testing.T) {
	s1, err := GenerateRandomSecret(64)
	if err != nil {
		t.Fatal("error:", err)
	}

	s2, err := GenerateRandomSecret(64)
	if err != nil {
		t.Fatal("error:", err)
	}

	if reflect.DeepEqual(s1, s2) {
		t.Fatalf("Both secret are equal")
	}
}
