package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	now := time.Now()
	claims := &jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(expiresIn)),
		Issuer:    "chirpy",
		Subject:   userID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(tokenSecret))
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(tokenSecret), nil
		},
		jwt.WithLeeway(5*time.Second),
	)
	if err != nil {
		return uuid.Nil, err
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return uuid.Nil, errors.New("invalid token claims")
	}

	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return uuid.Nil, errors.New("token expired")
	}

	return uuid.Parse(claims.Subject)
}

func MakeRefreshToken() (string, error) {
	buffer := make([]byte, 32)
	_, err := rand.Read(buffer)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(buffer), nil
}

func getAuthorizationValue(headers http.Header, authType string) (string, error) {
	header := headers.Get("Authorization")
	if header == "" {
		return "", errors.New("missing Authorization header")
	}

	authPrefix := authType + " "
	if len(header) < len(authPrefix) || header[:len(authPrefix)] != authPrefix {
		return "", errors.New("invalid Authorization header")
	}

	return header[len(authPrefix):], nil
}

func GetBearerToken(headers http.Header) (string, error) {
	return getAuthorizationValue(headers, "Bearer")
}

func GetAPIKey(headers http.Header) (string, error) {
	return getAuthorizationValue(headers, "ApiKey")
}
