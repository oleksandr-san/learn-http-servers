
-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
  $1,
  $2,
  $3,
  $4,
  $5
)
RETURNING *;


-- name: ListChirps :many
SELECT *
FROM chirps
WHERE (sqlc.narg('user_id')::uuid IS NULL OR user_id = sqlc.narg('user_id')::uuid)
ORDER BY
  CASE WHEN @sort_asc::bool THEN created_at END ASC,
  CASE WHEN NOT @sort_asc::bool THEN created_at END DESC;

-- name: GetChirpByID :one
SELECT * FROM chirps WHERE id = $1;

-- name: DeleteChirpByID :exec
DELETE FROM chirps WHERE id = $1;