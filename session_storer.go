package auth

import (
	"net/http"
	"time"

	"github.com/qor/auth/claims"
	"github.com/qor/session"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// SessionStorerInterface session storer interface for Auth
type SessionStorerInterface interface {
	// Get get claims from request
	Get(req *http.Request) (*claims.Claims, error)
	// Update update claims with session manager
	Update(w http.ResponseWriter, req *http.Request, claims *claims.Claims) error
	// Delete delete session
	Delete(w http.ResponseWriter, req *http.Request) error

	// Flash add flash message to session data
	Flash(w http.ResponseWriter, req *http.Request, message session.Message) error
	// Flashes returns a slice of flash messages from session data
	Flashes(w http.ResponseWriter, req *http.Request) []session.Message

	// SignedToken generate signed token with Claims
	SignedToken(claims *claims.Claims) (string, error)
	// ValidateClaims validate auth token
	ValidateClaims(tokenString string) (*claims.Claims, error)
}

// SessionStorer default session storer
type SessionStorer struct {
	SessionName    string
	SigningMethod  jose.SignatureAlgorithm
	SignedString   string
	SessionManager session.ManagerInterface
}

// Get get claims from request
func (sessionStorer *SessionStorer) Get(req *http.Request) (*claims.Claims, error) {
	tokenString := req.Header.Get("Authorization")

	// Get Token from Cookie
	if tokenString == "" {
		tokenString = sessionStorer.SessionManager.Get(req, sessionStorer.SessionName)
	}

	return sessionStorer.ValidateClaims(tokenString)
}

// Update update claims with session manager
func (sessionStorer *SessionStorer) Update(w http.ResponseWriter, req *http.Request, claims *claims.Claims) error {
	token, err := sessionStorer.SignedToken(claims)
	if err != nil {
		return err
	}
	return sessionStorer.SessionManager.Add(w, req, sessionStorer.SessionName, token)
}

// Delete delete claims from session manager
func (sessionStorer *SessionStorer) Delete(w http.ResponseWriter, req *http.Request) error {
	sessionStorer.SessionManager.Pop(w, req, sessionStorer.SessionName)
	return nil
}

// Flash add flash message to session data
func (sessionStorer *SessionStorer) Flash(w http.ResponseWriter, req *http.Request, message session.Message) error {
	return sessionStorer.SessionManager.Flash(w, req, message)
}

// Flashes returns a slice of flash messages from session data
func (sessionStorer *SessionStorer) Flashes(w http.ResponseWriter, req *http.Request) []session.Message {
	return sessionStorer.SessionManager.Flashes(w, req)
}

// SignedToken generate signed token with Claims
func (sessionStorer *SessionStorer) SignedToken(claims *claims.Claims) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: sessionStorer.SigningMethod,
		Key:       []byte(sessionStorer.SignedString),
	}, nil)
	if err != nil {
		return "", err
	}

	return jwt.Signed(signer).Claims(claims).CompactSerialize()
}

// ValidateClaims validate auth token
func (sessionStorer *SessionStorer) ValidateClaims(tokenString string) (*claims.Claims, error) {
	token, err := jwt.ParseSigned(tokenString)
	if err != nil {
		return nil, err
	}

	var claims claims.Claims
	err = token.Claims([]byte(sessionStorer.SignedString), &claims)
	if err != nil {
		return nil, err
	}

	return &claims, claims.Validate(jwt.Expected{Time: time.Now()})
}
