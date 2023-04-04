package firebase

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/takokun778/firebase-authentication-go-proxy/internal/model"
	"google.golang.org/api/option"
)

type Firebase struct {
	identityToolKit string
	secureToken     string
	apiKey          string
	httpClient      *http.Client
	firebaseAuth    *auth.Client
}

func New(
	identityToolKit string,
	secureToken string,
	apiKey string,
	secret string,
) (*Firebase, error) {
	opt := option.WithCredentialsJSON([]byte(secret))

	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		return nil, fmt.Errorf("error create firebase app: %w", err)
	}

	at, err := app.Auth(context.Background())
	if err != nil {
		return nil, fmt.Errorf("error create auth client: %w", err)
	}

	if identityToolKit == "" {
		return nil, fmt.Errorf("firebase api tool kit is empty")
	}

	if secureToken == "" {
		return nil, fmt.Errorf("firebase api secure token is empty")
	}

	if apiKey == "" {
		return nil, fmt.Errorf("firebase api key is empty")
	}

	return &Firebase{
		identityToolKit: identityToolKit,
		secureToken:     secureToken,
		apiKey:          apiKey,
		httpClient:      http.DefaultClient,
		firebaseAuth:    at,
	}, nil
}

func (fb *Firebase) SignUp(ctx context.Context, uid string, email string, password string) error {
	params := (&auth.UserToCreate{}).
		UID(uid).
		Email(email).
		EmailVerified(false).
		Password(password).
		DisplayName(uid).
		Disabled(false)

	if _, err := fb.firebaseAuth.CreateUser(ctx, params); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func (fb *Firebase) SignIn(ctx context.Context, email string, password string) (model.Token, error) {
	// https://firebase.google.com/docs/reference/rest/auth#section-sign-in-email-password
	endpoint := fmt.Sprintf("%s/v1/accounts:signInWithPassword?key=%s", fb.identityToolKit, fb.apiKey)

	type SignInRequest struct {
		Email             string `json:"email"`
		Password          string `json:"password"`
		ReturnSecureToken bool   `json:"returnSecureToken"`
	}

	req := SignInRequest{
		Email:             email,
		Password:          password,
		ReturnSecureToken: true,
	}

	var buf bytes.Buffer

	if err := json.NewEncoder(&buf).Encode(req); err != nil {
		return model.Token{}, fmt.Errorf("failed to encode json: %w", err)
	}

	res, err := fb.httpClient.Post(endpoint, "application/json", &buf)
	if err != nil {
		return model.Token{}, fmt.Errorf("failed to post: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return model.Token{}, fmt.Errorf("failed to read body: %w", err)
		}

		msg := fmt.Sprintf("firebase error. status code is %d, message is %v", res.StatusCode, string(body))

		return model.Token{}, fmt.Errorf(msg)
	}

	type SignInResponse struct {
		ExpiresIn    string `json:"expiresIn"`
		LocalID      string `json:"localId"`
		IDToken      string `json:"idToken"`
		RefreshToken string `json:"refreshToken"`
	}

	var resp SignInResponse

	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		return model.Token{}, fmt.Errorf("failed to decode json: %w", err)
	}

	log.Printf("resp: %#v", resp)

	strs := strings.Split(resp.IDToken, ".")

	tmpPayload, err := base64.RawStdEncoding.DecodeString(strs[1])
	if err != nil {
		return model.Token{}, fmt.Errorf("failed to decode payload: %w", err)
	}

	type Payload struct {
		UserID string `json:"user_id"`
	}

	var payload Payload

	if err := json.Unmarshal(tmpPayload, &payload); err != nil {
		return model.Token{}, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	return model.Token{
		IDToken:      resp.IDToken,
		RefreshToken: resp.RefreshToken,
	}, nil
}

func (fb *Firebase) Refresh(ctx context.Context, token string) (string, error) {
	// https://firebase.google.com/docs/reference/rest/auth?hl=ja#section-refresh-token
	endpoint := fmt.Sprintf("%s/v1/token?key=%s", fb.secureToken, fb.apiKey)

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", token)

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := fb.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to post: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read body: %w", err)
		}

		msg := fmt.Sprintf("firebase error. status code is %d, message is %v", res.StatusCode, string(body))

		return "", fmt.Errorf(msg)
	}

	type RefreshResponse struct {
		ExpiresIn    string `json:"expires_in"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		UserID       string `json:"user_id"`
		ProjectID    string `json:"project_id"`
	}

	var resp RefreshResponse

	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		return "", fmt.Errorf("failed to decode json: %w", err)
	}

	return resp.IDToken, nil
}

func (fb *Firebase) ChangePassword(ctx context.Context, uid string, password string) error {
	params := (&auth.UserToUpdate{}).Password(password)

	if _, err := fb.firebaseAuth.UpdateUser(ctx, uid, params); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

func (fb *Firebase) Verify(ctx context.Context, token string) error {
	if _, err := fb.firebaseAuth.VerifyIDToken(ctx, token); err != nil {
		return fmt.Errorf("failed to verify token: %w", err)
	}

	return nil
}

func (fb *Firebase) Delete(ctx context.Context, uid string) error {
	if err := fb.firebaseAuth.DeleteUser(ctx, uid); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}
