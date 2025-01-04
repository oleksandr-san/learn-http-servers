-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
  $1,
  $2,
  $3,
  $4,
  $5
)
RETURNING *;


-- name: UpdateUser :one
UPDATE users
SET
  updated_at = $2,
  email = COALESCE($3, email),
  hashed_password = COALESCE($4, hashed_password)
WHERE id = $1
RETURNING *;

-- name: DeleteAllUsers :exec
DELETE FROM users;


-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByRefreshToken :one
SELECT users.* FROM users
JOIN refresh_tokens ON users.id = refresh_tokens.user_id
WHERE refresh_tokens.token = $1;