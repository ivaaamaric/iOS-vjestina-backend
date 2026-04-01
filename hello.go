package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	mr "math/rand/v2"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	addr := envOr("ADDR", ":8080")
	dbPath := envOr("DB_PATH", "app.db")

	db, err := openDB(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	r := chi.NewRouter()
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Content-Type"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiErr("invalid_json"))
			return
		}
		req.Username = strings.TrimSpace(req.Username)
		if req.Username == "" || req.Password == "" {
			writeJSON(w, http.StatusBadRequest, apiErr("missing_fields"))
			return
		}

		userID, created, err := ensureUser(r.Context(), db, req.Username, req.Password)
		if err != nil {
			if errors.Is(err, errInvalidCredentials) {
				writeJSON(w, http.StatusUnauthorized, apiErr("invalid_credentials"))
				return
			}
			writeJSON(w, http.StatusInternalServerError, apiErr("server_error"))
			return
		}

		token, err := newToken()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiErr("server_error"))
			return
		}
		if err := storeToken(r.Context(), db, userID, token); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiErr("server_error"))
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"token":    token,
			"username": req.Username,
			"created":  created,
		})
	})

	r.Group(func(ar chi.Router) {
		ar.Use(authMiddleware(db))

		ar.Post("/logout", func(w http.ResponseWriter, r *http.Request) {
			tok := tokenFromRequest(r)
			_ = deleteToken(r.Context(), db, tok)
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		})

		ar.Get("/word", func(w http.ResponseWriter, r *http.Request) {
			user := mustUser(r)

			word, date, err := getOrCreateDailyWord(r.Context(), db, time.Now().UTC())
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, apiErr("server_error"))
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"date":     date,
				"word":     word,
				"username": user.Username,
			})
		})

		ar.Post("/attempt", func(w http.ResponseWriter, r *http.Request) {
			user := mustUser(r)
			var req struct {
				Guess string `json:"guess"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, apiErr("invalid_json"))
				return
			}
			req.Guess = strings.TrimSpace(strings.ToLower(req.Guess))
			if req.Guess == "" {
				writeJSON(w, http.StatusBadRequest, apiErr("missing_guess"))
				return
			}

			word, _, err := getOrCreateDailyWord(r.Context(), db, time.Now().UTC())
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, apiErr("server_error"))
				return
			}

			attemptNo, err := createAttempt(r.Context(), db, user.ID, req.Guess, word, time.Now().UTC())
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, apiErr("server_error"))
				return
			}

			// Client can fire-and-forget; we respond immediately.
			writeJSON(w, http.StatusAccepted, map[string]any{
				"accepted":  true,
				"attemptNo": attemptNo,
			})
		})

		ar.Get("/leaderboard", func(w http.ResponseWriter, r *http.Request) {
			user := mustUser(r)
			rows, err := leaderboard(r.Context(), db)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, apiErr("server_error"))
				return
			}

			// Sort by points desc then username asc, assign ranks.
			sort.Slice(rows, func(i, j int) bool {
				if rows[i].Points != rows[j].Points {
					return rows[i].Points > rows[j].Points
				}
				return rows[i].Username < rows[j].Username
			})
			out := make([]map[string]any, 0, len(rows))
			for i, row := range rows {
				out = append(out, map[string]any{
					"rank":     i + 1,
					"username": row.Username,
					"points":   row.Points,
					"isMe":     row.Username == user.Username,
				})
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"items":    out,
				"username": user.Username,
			})
		})
	})

	log.Printf("listening on %s (db=%s)", addr, dbPath)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatal(err)
	}
}

// ----- storage + auth -----

var errInvalidCredentials = errors.New("invalid credentials")

type authedUser struct {
	ID       int64
	Username string
}

type ctxKey string

const userCtxKey ctxKey = "user"

func mustUser(r *http.Request) authedUser {
	u, _ := r.Context().Value(userCtxKey).(authedUser)
	return u
}

func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path+"?_foreign_keys=on&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		return nil, err
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash BLOB NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS tokens (
			token TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS daily_words (
			date TEXT PRIMARY KEY,
			word TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS attempts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			date TEXT NOT NULL,
			guess TEXT NOT NULL,
			is_correct INTEGER NOT NULL,
			attempt_no INTEGER NOT NULL,
			points INTEGER NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_attempts_user_date ON attempts(user_id, date);`,
		`CREATE INDEX IF NOT EXISTS idx_attempts_date ON attempts(date);`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return err
		}
	}
	return nil
}

func ensureUser(ctx context.Context, db *sql.DB, username, password string) (userID int64, created bool, err error) {
	var id int64
	var pwHash []byte
	row := db.QueryRowContext(ctx, `SELECT id, password_hash FROM users WHERE username = ?`, username)
	switch scanErr := row.Scan(&id, &pwHash); {
	case scanErr == nil:
		if bcrypt.CompareHashAndPassword(pwHash, []byte(password)) != nil {
			return 0, false, errInvalidCredentials
		}
		return id, false, nil
	case errors.Is(scanErr, sql.ErrNoRows):
		hash, herr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if herr != nil {
			return 0, false, herr
		}
		res, ierr := db.ExecContext(ctx,
			`INSERT INTO users(username, password_hash, created_at) VALUES(?,?,?)`,
			username, hash, time.Now().UTC().Format(time.RFC3339),
		)
		if ierr != nil {
			return 0, false, ierr
		}
		newID, _ := res.LastInsertId()
		return newID, true, nil
	default:
		return 0, false, scanErr
	}
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// URL-safe, no padding.
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func storeToken(ctx context.Context, db *sql.DB, userID int64, token string) error {
	_, err := db.ExecContext(ctx, `INSERT INTO tokens(token, user_id, created_at) VALUES(?,?,?)`,
		token, userID, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

func deleteToken(ctx context.Context, db *sql.DB, token string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM tokens WHERE token = ?`, token)
	return err
}

func authMiddleware(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := tokenFromRequest(r)
			if tok == "" {
				writeJSON(w, http.StatusUnauthorized, apiErr("missing_token"))
				return
			}

			var uid int64
			var username string
			err := db.QueryRowContext(r.Context(), `
				SELECT u.id, u.username
				FROM tokens t
				JOIN users u ON u.id = t.user_id
				WHERE t.token = ?
			`, tok).Scan(&uid, &username)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, apiErr("invalid_token"))
				return
			}

			ctx := context.WithValue(r.Context(), userCtxKey, authedUser{ID: uid, Username: username})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func tokenFromRequest(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if h == "" {
		return ""
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// ----- daily word -----

var localWords = []string{
	"apple", "grape", "pearl", "light", "stone", "river", "mouse", "candy", "plant", "table",
}

func getOrCreateDailyWord(ctx context.Context, db *sql.DB, now time.Time) (word string, date string, err error) {
	date = now.Format("2006-01-02")
	row := db.QueryRowContext(ctx, `SELECT word FROM daily_words WHERE date = ?`, date)
	switch scanErr := row.Scan(&word); {
	case scanErr == nil:
		return word, date, nil
	case errors.Is(scanErr, sql.ErrNoRows):
		// Choose once/day and persist.
		word = localWords[mr.IntN(len(localWords))]
		_, ierr := db.ExecContext(ctx,
			`INSERT INTO daily_words(date, word, created_at) VALUES(?,?,?)`,
			date, word, time.Now().UTC().Format(time.RFC3339),
		)
		if ierr != nil {
			// If a race inserts first, just read it.
			row2 := db.QueryRowContext(ctx, `SELECT word FROM daily_words WHERE date = ?`, date)
			if err2 := row2.Scan(&word); err2 == nil {
				return word, date, nil
			}
			return "", "", ierr
		}
		return word, date, nil
	default:
		return "", "", scanErr
	}
}

// ----- attempts + leaderboard -----

func createAttempt(ctx context.Context, db *sql.DB, userID int64, guess, answer string, now time.Time) (attemptNo int, err error) {
	date := now.Format("2006-01-02")

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var maxNo sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(attempt_no) FROM attempts WHERE user_id = ? AND date = ?`, userID, date).Scan(&maxNo); err != nil {
		return 0, err
	}
	attemptNo = 1
	if maxNo.Valid {
		attemptNo = int(maxNo.Int64) + 1
	}

	isCorrect := 0
	points := 0
	if strings.EqualFold(guess, answer) {
		isCorrect = 1
		// Simple scoring: earlier win => more points.
		points = max(0, 7-attemptNo)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO attempts(user_id, date, guess, is_correct, attempt_no, points, created_at)
		VALUES(?,?,?,?,?,?,?)
	`, userID, date, guess, isCorrect, attemptNo, points, now.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return attemptNo, nil
}

type leaderboardRow struct {
	Username string
	Points   int
}

func leaderboard(ctx context.Context, db *sql.DB) ([]leaderboardRow, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT u.username, COALESCE(SUM(a.points), 0) AS points
		FROM users u
		LEFT JOIN attempts a ON a.user_id = u.id
		GROUP BY u.id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []leaderboardRow
	for rows.Next() {
		var r leaderboardRow
		if err := rows.Scan(&r.Username, &r.Points); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ----- helpers -----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiErr(code string) map[string]any {
	return map[string]any{"error": code}
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
