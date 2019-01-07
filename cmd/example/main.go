package main

import (
	"encoding/json"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/authority"
	"github.com/qor/auth/providers/dex"
	"github.com/qor/redirect_back"
	"github.com/qor/roles"
	"github.com/qor/session/manager"
)

type User struct {
	ID        uint      `gorm:"primary_key" json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	Name      string    `form:"name" json:"name,omitempty"`
	Email     string    `form:"email" json:"email,omitempty"`
	Login     string    `gorm:"unique;not null" form:"login" json:"login"`
	Image     string    `form:"image" json:"image,omitempty"`
}

var (
	// Initialize gorm DB
	gormDB, _ = gorm.Open("sqlite3", "sample.db")

	authConfig = auth.Config{
		DB:        gormDB,
		UserModel: User{},
		Redirector: &auth.Redirector{
			redirect_back.New(&redirect_back.Config{
				IgnoredPrefixes: []string{"/dex/"},
			})},
		SessionStorer: &auth.SessionStorer{
			SessionName:    "_auth_session",
			SessionManager: manager.SessionManager,
			SigningMethod:  jwt.SigningMethodHS256,
			SignedString:   "s3cr3tRandomSigningKey",
		},
	}

	// Initialize Auth with configuration
	Auth = auth.New(&authConfig)

	Authority = authority.New(&authority.Config{
		Auth: Auth,
		Role: roles.Global, // default configuration
		AccessDeniedHandler: func(w http.ResponseWriter, req *http.Request) { // redirect to auth page by default
			http.Redirect(w, req, "/auth/dex/login", http.StatusSeeOther)
		},
	})
)

func init() {
	// Migrate AuthIdentity model, AuthIdentity will be used to save auth info, like username/password, oauth token, you could change that.
	gormDB.AutoMigrate(&auth_identity.AuthIdentity{})
	gormDB.AutoMigrate(&User{})

	// Register Auth providers
	// Allow use dex
	dexProvider := dex.New(&dex.Config{
		ClientID:     "example-app",
		ClientSecret: "ZXhhbXBsZS1hcHAtc2VjcmV0",
		IssuerURL:    "http://127.0.0.1:5556/dex",
	})
	Auth.RegisterProvider(dexProvider)
}

type indexHandler struct{}

func (indexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data, err := json.Marshal(Auth.GetCurrentUser(r))
	if err != nil {
		panic(err)
	}
	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(data)
	if err != nil {
		panic(err)
	}
}

// Visit http://127.0.0.1:9000/auth/dex/login to login
func main() {
	mux := http.NewServeMux()

	// Mount Auth to Router
	mux.Handle("/auth/", Auth.NewServeMux())
	mux.Handle("/", Authority.Authorize()(indexHandler{}))
	println("Server is running on :9000")
	http.ListenAndServe(":9000", manager.SessionManager.Middleware(mux))
}
