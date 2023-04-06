package test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/deepmap/oapi-codegen/pkg/types"
	"github.com/google/uuid"
	"github.com/takokun778/firebase-authentication-go-proxy/internal/api"
	"github.com/takokun778/firebase-authentication-go-proxy/test/helper"
)

func TestScenario(t *testing.T) {
	t.Parallel()

	url := os.Getenv("APP_ENDPOINT")

	t.Run("シナリオテスト", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		client := helper.NewOpenAPIClient(t, url)

		password := uuid.New().String()

		email := fmt.Sprintf("%s@example.com", password)

		// サインアップ
		signUpRes, err := client.V1AuthSignUp(ctx, api.V1AuthSignUpRequestSchema{
			Email:    types.Email(email),
			Password: password,
		})
		if err != nil {
			t.Fatalf("failed to sign up: %v", err)
		}

		defer signUpRes.Body.Close()

		if signUpRes.StatusCode != 200 {
			t.Fatalf("status code is not 200: %d", signUpRes.StatusCode)
		}

		// サインイン
		signInRes, err := client.V1AuthSignIn(ctx, api.V1AuthSignInRequestSchema{
			Email:    types.Email(email),
			Password: password,
		})
		if err != nil {
			t.Fatalf("failed to sign in: %v", err)
		}

		defer signInRes.Body.Close()

		if signInRes.StatusCode != 200 {
			t.Fatalf("status code is not 200: %d", signInRes.StatusCode)
		}

		signInResBody, _ := io.ReadAll(signInRes.Body)

		var signInResSchema api.V1AuthSignInResponseSchema
		if err := json.Unmarshal(signInResBody, &signInResSchema); err != nil {
			t.Fatalf("failed marshal response: %s caused by %s", signInResBody, err)
		}

		idToken := signInResSchema.IdToken

		refreshToken := signInResSchema.RefreshToken

		client.Client = &http.Client{
			Transport: helper.NewAuthorizationHeaderTransport(t, idToken),
		}

		// トークン検証
		verifyRes, err := client.V1AuthVerify(ctx)
		if err != nil {
			t.Fatalf("failed to verify: %v", err)
		}

		defer verifyRes.Body.Close()

		if verifyRes.StatusCode != 200 {
			t.Fatalf("status code is not 200: %d", verifyRes.StatusCode)
		}

		// トークン更新
		refreshRes, err := client.V1AuthRefresh(ctx, api.V1AuthRefreshRequestSchema{
			RefreshToken: refreshToken,
		})
		if err != nil {
			t.Fatalf("failed to refresh: %v", err)
		}

		defer refreshRes.Body.Close()

		if refreshRes.StatusCode != 200 {
			t.Fatalf("status code is not 200: %d", refreshRes.StatusCode)
		}

		refreshResBody, _ := io.ReadAll(refreshRes.Body)

		var refreshResSchema api.V1AuthRefreshResponseSchema
		if err := json.Unmarshal(refreshResBody, &refreshResSchema); err != nil {
			t.Fatalf("failed marshal response: %s caused by %s", refreshResBody, err)
		}

		client.Client = &http.Client{
			Transport: helper.NewAuthorizationHeaderTransport(t, refreshResSchema.IdToken),
		}

		newPassword := uuid.New().String()

		// パスワード更新
		changePasswordRes, err := client.V1AuthChangePassword(ctx, api.V1AuthChangePasswordRequestSchema{
			Email:       types.Email(email),
			NewPassword: newPassword,
			OldPassword: password,
		})
		if err != nil {
			t.Fatalf("failed to change password: %v", err)
		}

		defer changePasswordRes.Body.Close()

		// 旧パスワードでログインに失敗する
		client = helper.NewOpenAPIClient(t, url)
		failureSignInRes, err := client.V1AuthSignIn(ctx, api.V1AuthSignInRequestSchema{
			Email:    types.Email(email),
			Password: password,
		})

		if err != nil {
			t.Fatalf("failed to sign in: %v", err)
		}

		defer failureSignInRes.Body.Close()

		if failureSignInRes.StatusCode != 401 {
			t.Fatalf("status code is not 401: %d", failureSignInRes.StatusCode)
		}

		// サインアウト
		client.Client = &http.Client{
			Transport: helper.NewAuthorizationHeaderTransport(t, refreshResSchema.IdToken),
		}
		signOutRes, err := client.V1AuthSignOut(ctx)
		if err != nil {
			t.Fatalf("failed to sign out: %v", err)
		}

		defer signOutRes.Body.Close()

		if signOutRes.StatusCode != 200 {
			t.Fatalf("status code is not 200: %d", signOutRes.StatusCode)
		}

		// リサイン(退会)
		resignRes, err := client.V1AuthResign(ctx, api.V1AuthResignRequestSchema{
			Email:    types.Email(email),
			Password: newPassword,
		})
		if err != nil {
			t.Fatalf("failed to resign: %v", err)
		}

		defer resignRes.Body.Close()

		if resignRes.StatusCode != 200 {
			t.Fatalf("status code is not 200: %d", resignRes.StatusCode)
		}

		// 退会後にサインインに失敗する
		client = helper.NewOpenAPIClient(t, url)

		failureSignInRes, err = client.V1AuthSignIn(ctx, api.V1AuthSignInRequestSchema{
			Email:    types.Email(email),
			Password: newPassword,
		})
		if err != nil {
			t.Fatalf("failed to sign in: %v", err)
		}

		defer failureSignInRes.Body.Close()

		if failureSignInRes.StatusCode != 401 {
			t.Fatalf("status code is not 401: %d", failureSignInRes.StatusCode)
		}
	})
}
