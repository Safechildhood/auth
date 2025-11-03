CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL,
    secret_phrase VARCHAR(255) NOT NULL,
    secret_phrase_hint VARCHAR(255) NOT NULL,
    fingerprints_hash VARCHAR(255)[] NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);
