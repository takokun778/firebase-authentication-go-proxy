package handler

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/takokun778/firebase-authentication-go-proxy/internal/api"
	"github.com/takokun778/firebase-authentication-go-proxy/internal/firebase"
)

var _ api.ServerInterface = &Handler{}

type Handler struct {
	firebase *firebase.Firebase
}

func New(
	firebase *firebase.Firebase,
) *Handler {
	return &Handler{
		firebase: firebase,
	}
}

// リサイン(退会)
// (DELETE /v1/auth)
func (hdl *Handler) V1AuthResign(ctx echo.Context) error {
	return nil
}

// パスワード更新
// (PUT /v1/auth/password)
func (hdl *Handler) V1AuthChangePassword(ctx echo.Context) error {
	return nil
}

// リフレッシュ
// (POST /v1/auth/refresh)
func (hdl *Handler) V1AuthRefresh(ctx echo.Context) error {
	var body api.V1AuthRefreshRequestSchema

	if err := (&echo.DefaultBinder{}).BindBody(ctx, &body); err != nil {
		return fmt.Errorf("error bind body: %w", err)
	}

	res, err := hdl.firebase.Refresh(ctx.Request().Context(), body.RefreshToken)
	if err != nil {
		return fmt.Errorf("error refresh: %w", err)
	}

	return ctx.JSON(http.StatusOK, res)
}

// サインイン
// (POST /v1/auth/signin)
func (hdl *Handler) V1AuthSignIn(ctx echo.Context) error {
	var body api.V1AuthSignInRequestSchema

	if err := (&echo.DefaultBinder{}).BindBody(ctx, &body); err != nil {
		return fmt.Errorf("error bind body: %w", err)
	}

	token, err := hdl.firebase.SignIn(ctx.Request().Context(), string(body.Email), body.Password)
	if err != nil {
		return fmt.Errorf("error sign in: %w", err)
	}

	res := api.V1AuthSignInResponseSchema{
		IdToken:      token.IDToken,
		RefreshToken: token.RefreshToken,
	}

	return ctx.JSON(http.StatusOK, res)
}

// サインアウト
// (GET /v1/auth/signout)
func (hdl *Handler) V1AuthSignOut(ctx echo.Context) error {
	return nil
}

// サインアップ
// (POST /v1/auth/signup)
func (hdl *Handler) V1AuthSignUp(ctx echo.Context) error {
	var body api.V1AuthSignInRequestSchema

	if err := (&echo.DefaultBinder{}).BindBody(ctx, &body); err != nil {
		return fmt.Errorf("error bind body: %w", err)
	}

	log.Printf("body: %#v", body)

	uid := uuid.New().String()

	if err := hdl.firebase.SignUp(ctx.Request().Context(), uid, string(body.Email), body.Password); err != nil {
		return fmt.Errorf("error sign up: %w", err)
	}

	return nil
}

// 検証
// (GET /v1/auth/verify)
func (hdl *Handler) V1AuthVerify(ctx echo.Context) error {
	if ctx.Request().Header.Get("Authorization") == "" {
		return fmt.Errorf("authorization header is empty")
	}

	token := strings.Split(ctx.Request().Header.Get("Authorization"), " ")

	if len(token) != 2 {
		return fmt.Errorf("authorization header is invalid")
	}

	if token[0] != "Bearer" {
		return fmt.Errorf("authorization header is invalid")
	}

	log.Printf("token: %s", token[1])

	if err := hdl.firebase.Verify(ctx.Request().Context(), token[1]); err != nil {
		return fmt.Errorf("error verify: %w", err)
	}

	return nil
}
