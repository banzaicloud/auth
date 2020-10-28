package auth

import (
	"net/http"
)

// RedirectorInterface redirector interface
type RedirectorInterface interface {
	// Redirect redirect after action
	Redirect(w http.ResponseWriter, req *http.Request, action string)
}
