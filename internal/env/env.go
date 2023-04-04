package env

import (
	"log"
	"os"
)

type Env struct {
	FirebaseSecret             string
	FirebaseAPIIdentityToolKit string
	FirebaseAPISecureToken     string
	FirebaseAPIKey             string
}

func New() *Env {
	env := &Env{
		FirebaseSecret:             os.Getenv("FIREBASE_SECRET"),
		FirebaseAPIIdentityToolKit: os.Getenv("FIREBASE_API_IDENTITY_TOOL_KIT"),
		FirebaseAPISecureToken:     os.Getenv("FIREBASE_API_SECURE_TOKEN"),
		FirebaseAPIKey:             os.Getenv("FIREBASE_API_KEY"),
	}

	log.Printf("env: %#v", env)

	return env
}
