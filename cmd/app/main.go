package main

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/takokun778/firebase-authentication-go-proxy/internal/api"
	"github.com/takokun778/firebase-authentication-go-proxy/internal/env"
	"github.com/takokun778/firebase-authentication-go-proxy/internal/firebase"
	"github.com/takokun778/firebase-authentication-go-proxy/internal/handler"
)

func main() {
	en := env.New()

	e := echo.New()

	e.Use(middleware.Logger())

	fb, err := firebase.New(
		en.FirebaseAPIIdentityToolKit,
		en.FirebaseAPISecureToken,
		en.FirebaseAPIKey,
		en.FirebaseSecret,
	)
	if err != nil {
		panic(err)
	}

	hdl := handler.New(fb)

	api.RegisterHandlers(e.Group("/api"), hdl)

	if err := e.Start(":8080"); err != nil {
		panic(err)
	}
}
