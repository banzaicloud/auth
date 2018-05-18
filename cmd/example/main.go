package main

import (
	"net/http"
	"time"

	"github.com/qor/redirect_back"

	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/providers/dex"
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

	// Initialize Auth with configuration
	Auth = auth.New(&auth.Config{
		DB:        gormDB,
		UserModel: User{},
		Redirector: &auth.Redirector{
			redirect_back.New(&redirect_back.Config{
				IgnoreFunc: func(r *http.Request) bool {
					println("ignoring", r.RequestURI)
					return true
				},
			})},
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

func main() {
	mux := http.NewServeMux()

	// Mount Auth to Router
	mux.Handle("/auth/", Auth.NewServeMux())
	http.ListenAndServe(":9000", manager.SessionManager.Middleware(mux))
}
