package main

import (
	// "fmt"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"learn-http-servers/internal/auth"
	"learn-http-servers/internal/database"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	tokenSecret    string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) resetMetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.platform != "dev" {
			w.WriteHeader(403)
			return
		}

		err := cfg.db.DeleteAllUsers(r.Context())
		if err != nil {
			log.Printf("Error deleting users: %s", err)
			w.WriteHeader(500)
			return
		}

		w.WriteHeader(200)
		cfg.fileserverHits.Store(0)
	})
}

func (cfg *apiConfig) metricServer() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/html")
		body := fmt.Sprintf(`
<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())
		w.Write([]byte(body))
	})
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

func (cfg *apiConfig) createUser(w http.ResponseWriter, r *http.Request) {
	type requestBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	request := requestBody{}
	err := decoder.Decode(&request)
	if err != nil {
		log.Printf("Error decoding request: %s", err)
		w.WriteHeader(500)
		return
	}

	id, err := uuid.NewV7()
	if err != nil {
		log.Printf("Error generating UUID: %s", err)
		w.WriteHeader(500)
		return
	}

	hash, err := auth.HashPassword(request.Password)
	if err != nil {
		log.Printf("Error hashing password: %s", err)
		w.WriteHeader(500)
		return
	}

	dbUser, err := cfg.db.CreateUser(r.Context(), database.CreateUserParams{
		ID:             id,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		Email:          request.Email,
		HashedPassword: hash,
	})
	if err != nil {
		log.Printf("Error creating user: %s", err)
		w.WriteHeader(500)
		return
	}

	user := User{
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email:     dbUser.Email,
	}

	data, err := json.Marshal(user)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	w.Write(data)
}

func (cfg *apiConfig) updateUser(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting bearer token: %s", err)
		w.WriteHeader(401)
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.tokenSecret)
	if err != nil {
		log.Printf("Error validating JWT: %s", err)
		w.WriteHeader(401)
		return
	}

	type requestBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)
	request := requestBody{}
	err = decoder.Decode(&request)
	if err != nil {
		log.Printf("Error decoding request: %s", err)
		w.WriteHeader(500)
		return
	}

	hash, err := auth.HashPassword(request.Password)
	if err != nil {
		log.Printf("Error hashing password: %s", err)
		w.WriteHeader(500)
		return
	}

	dbUser, err := cfg.db.UpdateUser(r.Context(), database.UpdateUserParams{
		ID:             userID,
		Email:          request.Email,
		UpdatedAt:      time.Now(),
		HashedPassword: hash,
	})

	if err != nil {
		log.Printf("Error updating user: %s", err)
		w.WriteHeader(500)
		return
	}

	user := User{
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email:     dbUser.Email,
	}

	data, err := json.Marshal(user)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(data)
}

func (cfg *apiConfig) createChirp(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting bearer token: %s", err)
		w.WriteHeader(401)
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.tokenSecret)
	if err != nil {
		log.Printf("Error validating JWT: %s", err)
		w.WriteHeader(401)
		return
	}

	type requestBody struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(r.Body)
	request := requestBody{}
	err = decoder.Decode(&request)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}

	type responseBody struct {
		Body      string     `json:"body,omitempty"`
		Valid     bool       `json:"valid"`
		Error     string     `json:"error,omitempty"`
		Id        *uuid.UUID `json:"id,omitempty"`
		UserId    *uuid.UUID `json:"user_id,omitempty"`
		CreatedAt *time.Time `json:"created_at,omitempty"`
		UpdatedAt *time.Time `json:"updated_at,omitempty"`
	}

	response := responseBody{
		Valid: true,
	}
	if len(request.Body) >= 140 {
		response.Valid = false
		response.Error = "Chirp is too long"
	}
	if response.Valid {
		response.Body = cleanChirp(request.Body)
	}

	id, err := uuid.NewV7()
	if err != nil {
		log.Printf("Error generating UUID: %s", err)
		w.WriteHeader(500)
		return
	}
	dbChirp, err := cfg.db.CreateChirp(r.Context(), database.CreateChirpParams{
		ID:        id,
		Body:      request.Body,
		UserID:    userID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	if err != nil {
		log.Printf("Error creating chirp: %s", err)
		w.WriteHeader(500)
		return
	}

	response.Id = &dbChirp.ID
	response.UserId = &dbChirp.UserID
	response.CreatedAt = &dbChirp.CreatedAt
	response.UpdatedAt = &dbChirp.UpdatedAt

	data, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if response.Valid {
		w.WriteHeader(201)
	} else {
		w.WriteHeader(400)
	}
	w.Write(data)
}

func cleanChirp(chirp string) string {
	forbiddenWords := map[string]interface{}{
		"kerfuffle": nil,
		"sharbert":  nil,
		"fornax":    nil,
	}

	cleanedWords := []string{}
	for _, word := range strings.Split(chirp, " ") {
		if _, ok := forbiddenWords[strings.ToLower(word)]; ok {
			cleanedWords = append(cleanedWords, "****")
		} else {
			cleanedWords = append(cleanedWords, word)
		}
	}

	return strings.Join(cleanedWords, " ")
}

type Chirp struct {
	Id        uuid.UUID `json:"id"`
	Body      string    `json:"body"`
	UserId    uuid.UUID `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (cfg *apiConfig) listChirps(w http.ResponseWriter, r *http.Request) {
	type responseBody []Chirp

	chirps, err := cfg.db.ListAllChirps(r.Context())
	if err != nil {
		log.Printf("Error listing chirps: %s", err)
		w.WriteHeader(500)
		return
	}

	response := responseBody{}
	for _, chirp := range chirps {
		response = append(response, struct {
			Id        uuid.UUID `json:"id"`
			Body      string    `json:"body"`
			UserId    uuid.UUID `json:"user_id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
		}{
			Id:        chirp.ID,
			Body:      chirp.Body,
			UserId:    chirp.UserID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
		})
	}

	data, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(data)
}

func (cfg *apiConfig) fingChirp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(id)
	if err != nil {
		log.Printf("Error parsing UUID: %s", err)
		w.WriteHeader(400)
		return
	}

	dbChirp, err := cfg.db.GetChirpByID(r.Context(), chirpID)
	if err != nil {
		log.Printf("Error finding chirp: %s", err)
		if err == sql.ErrNoRows {
			w.WriteHeader(404)
		} else {
			w.WriteHeader(500)
		}
		return
	}

	response := Chirp{
		Id:        dbChirp.ID,
		Body:      dbChirp.Body,
		UserId:    dbChirp.UserID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
	}
	data, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(data)
}

func (cfg *apiConfig) deleteChirp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(id)
	if err != nil {
		log.Printf("Error parsing UUID: %s", err)
		w.WriteHeader(400)
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting bearer token: %s", err)
		w.WriteHeader(401)
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.tokenSecret)
	if err != nil {
		log.Printf("Error validating JWT: %s", err)
		w.WriteHeader(401)
		return
	}

	dbChirp, err := cfg.db.GetChirpByID(r.Context(), chirpID)
	if err != nil {
		log.Printf("Error finding chirp: %s", err)
		if err == sql.ErrNoRows {
			w.WriteHeader(404)
		} else {
			w.WriteHeader(500)
		}
		return
	}

	if dbChirp.UserID != userID {
		log.Printf("User does not own chirp")
		w.WriteHeader(403)
		return
	}

	err = cfg.db.DeleteChirpByID(r.Context(), chirpID)
	if err != nil {
		log.Printf("Error deleting chirp: %s", err)
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(204)
}

type LoginResponse struct {
	User
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

func (cfg *apiConfig) login(w http.ResponseWriter, r *http.Request) {
	type requestBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	request := requestBody{}
	err := decoder.Decode(&request)
	if err != nil {
		log.Printf("Error decoding request: %s", err)
		w.WriteHeader(400)
		return
	}

	dbUser, err := cfg.db.GetUserByEmail(r.Context(), request.Email)
	if err != nil {
		log.Printf("Error finding user: %s", err)
		w.WriteHeader(401)
		return
	}

	err = auth.CheckPasswordHash(request.Password, dbUser.HashedPassword)
	if err != nil {
		log.Printf("Error checking password: %s", err)
		w.WriteHeader(401)
		return
	}

	expiresIn := time.Hour
	token, err := auth.MakeJWT(dbUser.ID, cfg.tokenSecret, expiresIn)
	if err != nil {
		log.Printf("Error making JWT: %s", err)
		w.WriteHeader(500)
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		log.Printf("Error making refresh token: %s", err)
		w.WriteHeader(500)
		return
	}

	now := time.Now()
	refreshExpiresIn := time.Hour * 24 * 60
	_, err = cfg.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		CreatedAt: now,
		UpdatedAt: now,
		UserID:    dbUser.ID,
		ExpiresAt: now.Add(refreshExpiresIn),
	})
	if err != nil {
		log.Printf("Error creating refresh token: %s", err)
		w.WriteHeader(500)
		return
	}

	user := LoginResponse{
		User: User{
			ID:        dbUser.ID,
			CreatedAt: dbUser.CreatedAt,
			UpdatedAt: dbUser.UpdatedAt,
			Email:     dbUser.Email,
		},
		Token:        token,
		RefreshToken: refreshToken,
	}

	data, err := json.Marshal(user)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(data)
}

func (cfg *apiConfig) refreshToken(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting bearer token: %s", err)
		w.WriteHeader(401)
		return
	}

	dbToken, err := cfg.db.GetRefreshToken(r.Context(), refreshToken)
	if err != nil {
		log.Printf("Error finding token: %s", err)
		w.WriteHeader(401)
		return
	}

	if dbToken.RevokedAt.Valid || dbToken.ExpiresAt.Before(time.Now()) {
		log.Printf("Token is revoked or expired")
		w.WriteHeader(401)
		return
	}

	dbUser, err := cfg.db.GetUserByRefreshToken(r.Context(), refreshToken)
	if err != nil {
		log.Printf("Error finding user: %s", err)
		w.WriteHeader(401)
		return
	}

	expiresIn := time.Hour
	token, err := auth.MakeJWT(dbUser.ID, cfg.tokenSecret, expiresIn)
	if err != nil {
		log.Printf("Error making JWT: %s", err)
		w.WriteHeader(500)
		return
	}

	type responseBody struct {
		Token string `json:"token"`
	}
	response := responseBody{
		Token: token,
	}
	data, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(data)
}

func (cfg *apiConfig) revokeToken(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting bearer token: %s", err)
		w.WriteHeader(401)
		return
	}

	_, err = cfg.db.RevokeRefreshToken(r.Context(), database.RevokeRefreshTokenParams{
		Token:     refreshToken,
		RevokedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	if err != nil {
		log.Printf("Error revoking token: %s", err)
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(204)
}

func checkHealth(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func main() {
	godotenv.Load()

	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Error opening database: %s", err)
	}

	apiCfg := apiConfig{
		db:          database.New(db),
		platform:    os.Getenv("PLATFORM"),
		tokenSecret: os.Getenv("TOKEN_SECRET"),
	}

	srv := http.Server{}
	srv.Addr = ":8080"

	mux := http.NewServeMux()
	srv.Handler = mux

	mux.Handle(
		"/app/",
		apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))),
	)

	mux.Handle("GET /admin/metrics", apiCfg.metricServer())
	mux.Handle("POST /admin/reset", apiCfg.resetMetricsHandler())

	mux.HandleFunc("GET /api/healthz", checkHealth)

	mux.HandleFunc("POST /api/users", apiCfg.createUser)
	mux.HandleFunc("PUT /api/users", apiCfg.updateUser)

	mux.HandleFunc("POST /api/chirps", apiCfg.createChirp)
	mux.HandleFunc("GET /api/chirps", apiCfg.listChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.fingChirp)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirp)

	mux.HandleFunc("POST /api/login", apiCfg.login)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshToken)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeToken)

	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		// We received an interrupt signal, shut down.
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			log.Printf("HTTP server Shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		// Error starting or closing listener:
		log.Fatalf("HTTP server ListenAndServe: %v", err)
	}

	<-idleConnsClosed
}
