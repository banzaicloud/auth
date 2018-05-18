package dex

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/coreos/go-oidc"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/claims"
	"github.com/qor/qor/utils"
	"golang.org/x/oauth2"
)

const exampleAppState = "I wish to wash my irish wristwatch"

// DexProvider provide login with dex method
type DexProvider struct {
	*Config
	provider *oidc.Provider
}

// Config github Config
type Config struct {
	ClientID         string
	ClientSecret     string
	IssuerURL        string
	RedirectURL      string
	Scopes           []string
	AuthorizeHandler func(*auth.Context) (*claims.Claims, error)
}

func New(config *Config) *DexProvider {
	if config == nil {
		config = &Config{}
	}

	provider := &DexProvider{Config: config}

	if config.ClientID == "" {
		panic(errors.New("Dex's ClientID can't be blank"))
	}

	if config.ClientSecret == "" {
		panic(errors.New("Dex's ClientSecret can't be blank"))
	}

	if config.IssuerURL == "" {
		panic(errors.New("Dex's IssuerURL can't be blank"))
	}

	if config.Scopes == nil {
		config.Scopes = []string{"openid", "profile", "email", "federated:id"}
	}

	// TODO(ericchiang): Retry with backoff
	ctx := oidc.ClientContext(context.Background(), http.DefaultClient)
	dexProvider, err := oidc.NewProvider(ctx, provider.IssuerURL)
	if err != nil {
		panic(fmt.Errorf("Failed to query provider %q: %v", provider.IssuerURL, err))
	}

	provider.provider = dexProvider

	verifier := dexProvider.Verifier(&oidc.Config{ClientID: config.ClientID})

	if config.AuthorizeHandler == nil {
		config.AuthorizeHandler = func(context *auth.Context) (*claims.Claims, error) {
			var (
				schema       auth.Schema
				authInfo     auth_identity.Basic
				authIdentity = reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
				req          = context.Request
				tx           = context.Auth.GetDB(req)
				w            = context.Writer
			)

			var (
				err   error
				token *oauth2.Token
			)

			ctx := oidc.ClientContext(req.Context(), http.DefaultClient)
			oauth2Config := provider.OAuthConfig(context)
			switch req.Method {
			case "GET":
				// Authorization redirect callback from OAuth2 auth flow.
				if errMsg := req.FormValue("error"); errMsg != "" {
					http.Error(w, errMsg+": "+req.FormValue("error_description"), http.StatusBadRequest)
					return nil, err
				}
				code := req.FormValue("code")
				if code == "" {
					http.Error(w, fmt.Sprintf("no code in request: %q", req.Form), http.StatusBadRequest)
					return nil, err
				}
				state := req.FormValue("state")

				claims, err := context.Auth.SessionStorer.ValidateClaims(state)

				if err != nil || claims.Valid() != nil || claims.Subject != "state" {
					return nil, auth.ErrUnauthorized
				}

				if err != nil {
					return nil, err
				}

				token, err = oauth2Config.Exchange(ctx, code)

			case "POST":
				// Form request from frontend to refresh a token.
				refresh := req.FormValue("refresh_token")
				if refresh == "" {
					err = fmt.Errorf("no refresh_token in request: %q", req.Form)
					http.Error(w, err.Error(), http.StatusBadRequest)
					return nil, err
				}
				t := &oauth2.Token{
					RefreshToken: refresh,
					Expiry:       time.Now().Add(-time.Hour),
				}
				token, err = oauth2Config.TokenSource(ctx, t).Token()
			default:
				err = fmt.Errorf("method not implemented: %s", req.Method)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return nil, err
			}

			if err != nil {
				err = fmt.Errorf("failed to get token: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return nil, err
			}

			rawIDToken, ok := token.Extra("id_token").(string)
			if !ok {
				err = fmt.Errorf("no id_token in token response")
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return nil, err
			}

			idToken, err := verifier.Verify(req.Context(), rawIDToken)
			if err != nil {
				err = fmt.Errorf("Failed to verify ID token: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return nil, err
			}
			var claims jwt.MapClaims
			err = idToken.Claims(&claims)
			// TODO error handling
			fmt.Printf("Claims: %#v\n", claims)

			authInfo.Provider = provider.GetName()
			authInfo.UID = claims["sub"].(string) // Dex identifier

			if !tx.Model(authIdentity).Where(authInfo).Scan(&authInfo).RecordNotFound() {
				return authInfo.ToClaims(), nil
			}

			{
				schema.Provider = provider.GetName()
				schema.UID = claims["sub"].(string)
				schema.Name = claims["name"].(string)
				schema.Email = claims["email"].(string)
				//schema.Image = user.GetAvatarURL()
				schema.RawInfo = claims
			}
			if _, userID, err := context.Auth.UserStorer.Save(&schema, context); err == nil {
				if userID != "" {
					authInfo.UserID = userID
				}
			} else {
				return nil, err
			}

			if err = tx.Where(authInfo).FirstOrCreate(authIdentity).Error; err == nil {
				return authInfo.ToClaims(), nil
			}

			return nil, err
		}
	}

	return provider
}

// GetName return provider name
func (DexProvider) GetName() string {
	return "dex"
}

// ConfigAuth config auth
func (provider DexProvider) ConfigAuth(*auth.Auth) {
}

// OAuthConfig return oauth config based on configuration
func (provider DexProvider) OAuthConfig(context *auth.Context) *oauth2.Config {
	var (
		config = provider.Config
		req    = context.Request
		scheme = req.URL.Scheme
	)

	if scheme == "" {
		scheme = "http://"
	}

	return &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     provider.provider.Endpoint(),
		RedirectURL:  scheme + req.Host + context.Auth.AuthURL("dex/callback"),
		Scopes:       config.Scopes,
	}
}

// Login implemented login with github provider
func (provider DexProvider) Login(context *auth.Context) {
	claims := claims.Claims{}
	claims.Subject = "state"
	signedToken := context.Auth.SessionStorer.SignedToken(&claims)

	url := provider.OAuthConfig(context).AuthCodeURL(signedToken)
	http.Redirect(context.Writer, context.Request, url, http.StatusFound)
}

// Logout implemented logout with github provider
func (DexProvider) Logout(context *auth.Context) {
}

// Register implemented register with github provider
func (provider DexProvider) Register(context *auth.Context) {
	provider.Login(context)
}

// Callback implement Callback with github provider
func (provider DexProvider) Callback(context *auth.Context) {
	context.Auth.LoginHandler(context, provider.AuthorizeHandler)
}

// ServeHTTP implement ServeHTTP with github provider
func (DexProvider) ServeHTTP(*auth.Context) {
}
