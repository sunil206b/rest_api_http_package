package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	listUserRe   = regexp.MustCompile(`^\/users[\/]*$`)
	getUserRe    = regexp.MustCompile(`^\/users\/(\d+)$`)
	createUserRe = regexp.MustCompile(`^\/users[\/]*$`)
	headerTokenRe = regexp.MustCompile(`^Bearer\s([a-zA-Z0-9\.\-_]+)$`)
)

type user struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type datastore struct {
	m map[string]user
	*sync.RWMutex
}

type userHandler struct {
	store *datastore
	key []byte `json:"-"`
}

type authHandler struct {
	key []byte
}

func (ah *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost:
		ah.Token(w, r)
		return
	default:
		notFound(w, r)
		return
	}
}

type CustomeClaims struct {
	Username string
	jwt.StandardClaims
}

func (ah *authHandler) Token(w http.ResponseWriter, r *http.Request) {
	req := struct {
		User, Pwd string
	}{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		internalServerError(w, r)
		return
	}
	if !checkCredentials(req.User, req.Pwd) {
		unauthorized(w, r)
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, CustomeClaims{
		Username: req.User,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().AddDate(0, 0, 1).Unix(),
			Issuer: "http://example.com",
		},
	})
	tkn, err := token.SignedString(ah.key)
	if err != nil {
		unauthorized(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct{JWT string}{JWT: tkn})
}

func checkCredentials(user, pwd string) bool {
	return user == "admin" && pwd == "secret"
}

func authorizer(key []byte) func(w http.ResponseWriter, r *http.Request) bool {
	return func(w http.ResponseWriter, r *http.Request) bool {
		matches := headerTokenRe.FindStringSubmatch(r.Header.Get("Authorization"))
		if len(matches) < 2 {
			return false
		}

		token, err := jwt.ParseWithClaims(matches[1], &CustomeClaims{}, func(t *jwt.Token) (interface{}, error) {
			return key, nil
		})

		if err != nil {
			return false
		}
		tkn, ok := token.Claims.(*CustomeClaims)
		if !ok {
			return false
		}

		if err := tkn.Valid(); err != nil {
			return false
		}
		fmt.Printf("%+v", tkn)
		return true
	}
}

func (uh *userHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !authorizer(uh.key)(w, r) {
		unauthorized(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && listUserRe.MatchString(r.URL.Path):
		uh.List(w, r)
		return
	case r.Method == http.MethodGet && getUserRe.MatchString(r.URL.Path):
		uh.Get(w, r)
		return
	case r.Method == http.MethodPost && createUserRe.MatchString(r.URL.Path):
		uh.Create(w, r)
		return
	default:
		notFound(w, r)
		return
	}
}

func notFound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"error": "not found"}`))
}
func internalServerError(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(`{"error": "internal server error"}`))
}
func badRequest(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(`{"error": "bad request"}`))
}

func unauthorized(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"error": "not authorized"}`))
}

func (uh *userHandler) List(w http.ResponseWriter, r *http.Request) {
	users := make([]user, 0, len(uh.store.m))
	uh.store.RWMutex.RLock()
	for _, u := range uh.store.m {
		users = append(users, u)
	}
	uh.store.RWMutex.RUnlock()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(&users)
}

func (uh *userHandler) Get(w http.ResponseWriter, r *http.Request) {
	matches := getUserRe.FindStringSubmatch(r.URL.Path)
	if len(matches) < 2 {
		notFound(w, r)
		return
	}
	uh.store.RWMutex.RLock()
	user, ok := uh.store.m[matches[1]]
	uh.store.RWMutex.RUnlock()
	if !ok {
		internalServerError(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(&user)
}

func (uh *userHandler) Create(w http.ResponseWriter, r *http.Request) {
	var u user
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		badRequest(w, r)
		return
	}
	uh.store.RWMutex.Lock()
	uh.store.m[u.ID] = u
	uh.store.RWMutex.Unlock()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(&u)
}

var secretKey = []byte("secret")
func main() {
	userH := &userHandler{
		store: &datastore{
			m: map[string]user{
				"1": {ID: "1", Name: "bob"},
			},
			RWMutex: &sync.RWMutex{},
		},
		key: secretKey,
	}
	authH := &authHandler{key: secretKey}
	mux := http.NewServeMux()
	mux.Handle("/users", userH)
	mux.Handle("/users/", userH)
	mux.Handle("/auth", authH)
	http.ListenAndServe(":8080", mux)
}
