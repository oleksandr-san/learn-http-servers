-- +goose Up
-- id: a UUID that will serve as the primary key
-- created_at: a TIMESTAMP that can not be null
-- updated_at: a TIMESTAMP that can not be null
-- email: TEXT that can not be null and must be unique
CREATE TABLE users (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  email TEXT NOT NULL UNIQUE
);

-- +goose Down
DROP TABLE users;