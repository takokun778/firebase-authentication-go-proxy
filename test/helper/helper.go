package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/deepmap/oapi-codegen/pkg/types"
	"github.com/google/uuid"
	"github.com/takokun778/firebase-authentication-go-proxy/internal/api"
)

func NewOpenAPIClient(t *testing.T, url string) *api.Client {
	t.Helper()

	client, err := api.NewClient(url + "/api")
	if err != nil {
		t.Error(err)
	}

	return client
}

type AuthorizationHeaderTransport struct {
	T         *testing.T
	IDToken   string
	Transport http.RoundTripper
}

func NewAuthorizationHeaderTransport(
	t *testing.T,
	idToken string,
) *AuthorizationHeaderTransport {
	t.Helper()

	return &AuthorizationHeaderTransport{
		T:         t,
		IDToken:   idToken,
		Transport: http.DefaultTransport,
	}
}

func (aht *AuthorizationHeaderTransport) transport() http.RoundTripper {
	aht.T.Helper()

	return aht.Transport
}

func (aht *AuthorizationHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	aht.T.Helper()

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", aht.IDToken))

	res, err := aht.transport().RoundTrip(req)
	if err != nil {
		return nil, err
	}

	return res, err
}

type User struct {
	*testing.T
	EMail        string
	Password     string
	IDToken      string
	RefreshToken string
}

func NewUser(
	t *testing.T,
	url string,
) User {
	t.Helper()

	ctx := context.Background()

	password := uuid.New().String()

	email := fmt.Sprintf("%s@example.com", password)

	client, err := api.NewClient(url + "/api")
	if err != nil {
		t.Fatalf("failed to create openapi client: %v", err)
	}

	suRes, err := client.V1AuthSignUp(ctx, api.V1AuthSignUpRequestSchema{
		Email:    types.Email(email),
		Password: password,
	})
	if err != nil {
		t.Fatalf("failed to sign up: %v", err)
	}

	defer suRes.Body.Close()

	siRes, err := client.V1AuthSignIn(ctx, api.V1AuthSignInRequestSchema{
		Email:    types.Email(email),
		Password: password,
	})
	if err != nil {
		t.Fatalf("failed to sign in: %v", err)
	}

	defer siRes.Body.Close()

	body, _ := io.ReadAll(siRes.Body)

	var response api.V1AuthSignInResponseSchema
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("failed marshal response: %s caused by %s", body, err)
	}

	return User{
		T:            t,
		EMail:        fmt.Sprintf("%s@example.com", password),
		Password:     password,
		IDToken:      response.IdToken,
		RefreshToken: response.RefreshToken,
	}
}

func (u User) SignOut(
	t *testing.T,
) error {
	return nil
}
