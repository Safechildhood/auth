package postgresql

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/safechildhood/auth/internal/domain"
)

type Users struct {
	pool *pgxpool.Pool

	tableName string
}

func NewUsers(pool *pgxpool.Pool, tableName string) *Users {
	return &Users{
		pool:      pool,
		tableName: tableName,
	}
}

func (u *Users) Exists(ctx context.Context, email string) (bool, error) {
	query := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s WHERE email = $1)", u.tableName)

	var exists bool

	err := u.pool.QueryRow(ctx, query, email).Scan(&exists)

	return exists, err
}

func (u *Users) Get(ctx context.Context, id uuid.UUID) (domain.User, error) {
	query := fmt.Sprintf("SELECT * FROM %s WHERE id = $1", u.tableName)

	rows, err := u.pool.Query(ctx, query, id)
	if err != nil {
		return domain.User{}, err
	}

	user, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[domain.User])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, domain.ErrUserNotFound
		}

		return domain.User{}, err
	}

	return user, nil
}

func (u *Users) GetByEmail(ctx context.Context, email string) (domain.User, error) {
	query := fmt.Sprintf("SELECT * FROM %s WHERE email = $1", u.tableName)

	rows, err := u.pool.Query(ctx, query, email)
	if err != nil {
		return domain.User{}, err
	}

	user, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[domain.User])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, domain.ErrUserNotFound
		}

		return domain.User{}, err
	}

	return user, nil
}

func (u *Users) Create(ctx context.Context, user domain.User) error {
	query := fmt.Sprintf(
		`INSERT INTO %s (id, email, password_hash, salt, secret_phrase, secret_phrase_hint, fingerprints_hash, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		u.tableName,
	)

	if _, err := u.pool.Exec(ctx, query,
		user.ID,
		user.Email,
		user.PasswordHash,
		user.Salt,
		user.SecretPhrase,
		user.SecretPhraseHint,
		user.FingerprintsHash,
		user.CreatedAt.Format(time.RFC3339),
		user.UpdatedAt.Format(time.RFC3339),
	); err != nil {
		return err
	}

	return nil
}

func (u *Users) UpdatePassword(ctx context.Context, id uuid.UUID, newPasswordHash string) error {
	query := fmt.Sprintf("UPDATE %s SET password_hash = $1 WHERE id = $2", u.tableName)

	commandTag, err := u.pool.Exec(ctx, query, newPasswordHash, id)
	if err != nil {
		return err
	}

	if commandTag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

func (u *Users) UpdatePasswordByEmail(ctx context.Context, email, newPasswordHash string) error {
	query := fmt.Sprintf("UPDATE %s SET password_hash = $1 WHERE email = $2", u.tableName)

	commandTag, err := u.pool.Exec(ctx, query, newPasswordHash, email)
	if err != nil {
		return err
	}

	if commandTag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

func (u *Users) ContainsFingerprint(ctx context.Context, id uuid.UUID, fingerprintHash string) (bool, error) {
	query := fmt.Sprintf(
		`SELECT EXISTS(
			SELECT 1 FROM %s
			WHERE id = $1 AND $2 = ANY(fingerprints_hash)
		)`,
		u.tableName,
	)

	var exists bool

	if err := u.pool.QueryRow(ctx, query, id, fingerprintHash).Scan(&exists); err != nil {
		return false, err
	}

	return exists, nil
}

func (u *Users) AddFingerprint(ctx context.Context, id uuid.UUID, fingerprintHash string) error {
	query := fmt.Sprintf(
		`UPDATE %s 
		SET fingerprints_hash = array_append(fingerprints_hash, $1),
			updated_at = $2
		WHERE id = $3`,
		u.tableName,
	)

	if _, err := u.pool.Exec(ctx, query,
		fingerprintHash,
		time.Now().Format(time.RFC3339),
		id,
	); err != nil {
		return err
	}

	return nil
}
