package auth

import "testing"

func TestCheckPassword(t *testing.T) {
	hash, err := HashPassword("password1")
	if err != nil {
		t.Fatal(err)
	}

	err = CheckPasswordHash("password1", hash)
	if err != nil {
		t.Fatal(err)
	}

	err = CheckPasswordHash("password2", hash)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
