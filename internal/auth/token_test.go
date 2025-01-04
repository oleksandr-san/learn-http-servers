package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidToken(t *testing.T) {
	tokenSecret := "1234"
	userID := uuid.New()
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT: %v", err)
	}

	parsedUserID, err := ValidateJWT(token, tokenSecret)
	if err != nil {
		t.Fatalf("ValidateJWT: %v", err)
	}
	if parsedUserID != userID {
		t.Fatalf("expected %v, got %v", userID, parsedUserID)
	}
}

func TestWrongToken(t *testing.T) {
	tokenSecret := "1234"
	userID := uuid.New()
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT: %v", err)
	}

	_, err = ValidateJWT(token, "12345")
	if err == nil {
		t.Fatalf("ValidateJWT: %v", err)
	}
}

func TestExpiredToken(t *testing.T) {

	tokenSecret := "1234"
	userID := uuid.New()
	expiresIn := time.Nanosecond

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT: %v", err)
	}

	time.Sleep(time.Microsecond * 10)
	_, err = ValidateJWT(token, tokenSecret)
	if err == nil {
		t.Fatalf("ValidateJWT: %v", err)
	}
}

func TestGetBearerToken(t *testing.T) {
	token, err := GetBearerToken(http.Header{"Authorization": []string{"Bearer token"}})
	if err != nil {
		t.Fatalf("GetBearerToken: %v", err)
	}
	if token != "token" {
		t.Fatalf("expected token, got %s", token)
	}
}
