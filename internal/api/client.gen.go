// Package api provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.12.4 DO NOT EDIT.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// RequestEditorFn  is the function signature for the RequestEditor callback function
type RequestEditorFn func(ctx context.Context, req *http.Request) error

// Doer performs HTTP requests.
//
// The standard http.Client implements this interface.
type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client which conforms to the OpenAPI3 specification for this service.
type Client struct {
	// The endpoint of the server conforming to this interface, with scheme,
	// https://api.deepmap.com for example. This can contain a path relative
	// to the server, such as https://api.deepmap.com/dev-test, and all the
	// paths in the swagger spec will be appended to the server.
	Server string

	// Doer for performing requests, typically a *http.Client with any
	// customized settings, such as certificate chains.
	Client HttpRequestDoer

	// A list of callbacks for modifying requests which are generated before sending over
	// the network.
	RequestEditors []RequestEditorFn
}

// ClientOption allows setting custom parameters during construction
type ClientOption func(*Client) error

// Creates a new Client, with reasonable defaults
func NewClient(server string, opts ...ClientOption) (*Client, error) {
	// create a client with sane default values
	client := Client{
		Server: server,
	}
	// mutate client and add all optional params
	for _, o := range opts {
		if err := o(&client); err != nil {
			return nil, err
		}
	}
	// ensure the server URL always has a trailing slash
	if !strings.HasSuffix(client.Server, "/") {
		client.Server += "/"
	}
	// create httpClient, if not already present
	if client.Client == nil {
		client.Client = &http.Client{}
	}
	return &client, nil
}

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HttpRequestDoer) ClientOption {
	return func(c *Client) error {
		c.Client = doer
		return nil
	}
}

// WithRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithRequestEditorFn(fn RequestEditorFn) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, fn)
		return nil
	}
}

// The interface specification for the client above.
type ClientInterface interface {
	// V1AuthResign request with any body
	V1AuthResignWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	V1AuthResign(ctx context.Context, body V1AuthResignJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// V1AuthChangePassword request with any body
	V1AuthChangePasswordWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	V1AuthChangePassword(ctx context.Context, body V1AuthChangePasswordJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// V1AuthRefresh request with any body
	V1AuthRefreshWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	V1AuthRefresh(ctx context.Context, body V1AuthRefreshJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// V1AuthSignIn request with any body
	V1AuthSignInWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	V1AuthSignIn(ctx context.Context, body V1AuthSignInJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// V1AuthSignOut request
	V1AuthSignOut(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error)

	// V1AuthSignUp request with any body
	V1AuthSignUpWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	V1AuthSignUp(ctx context.Context, body V1AuthSignUpJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// V1AuthVerify request
	V1AuthVerify(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) V1AuthResignWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewV1AuthResignRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) V1AuthResign(ctx context.Context, body V1AuthResignJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewV1AuthResignRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) V1AuthChangePasswordWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewV1AuthChangePasswordRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) V1AuthChangePassword(ctx context.Context, body V1AuthChangePasswordJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewV1AuthChangePasswordRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) V1AuthRefreshWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewV1AuthRefreshRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) V1AuthRefresh(ctx context.Context, body V1AuthRefreshJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewV1AuthRefreshRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) V1AuthSignInWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewV1AuthSignInRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) V1AuthSignIn(ctx context.Context, body V1AuthSignInJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewV1AuthSignInRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) V1AuthSignOut(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewV1AuthSignOutRequest(c.Server)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) V1AuthSignUpWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewV1AuthSignUpRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) V1AuthSignUp(ctx context.Context, body V1AuthSignUpJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewV1AuthSignUpRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) V1AuthVerify(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewV1AuthVerifyRequest(c.Server)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewV1AuthResignRequest calls the generic V1AuthResign builder with application/json body
func NewV1AuthResignRequest(server string, body V1AuthResignJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewV1AuthResignRequestWithBody(server, "application/json", bodyReader)
}

// NewV1AuthResignRequestWithBody generates requests for V1AuthResign with any type of body
func NewV1AuthResignRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/auth")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("DELETE", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewV1AuthChangePasswordRequest calls the generic V1AuthChangePassword builder with application/json body
func NewV1AuthChangePasswordRequest(server string, body V1AuthChangePasswordJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewV1AuthChangePasswordRequestWithBody(server, "application/json", bodyReader)
}

// NewV1AuthChangePasswordRequestWithBody generates requests for V1AuthChangePassword with any type of body
func NewV1AuthChangePasswordRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/auth/password")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("PUT", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewV1AuthRefreshRequest calls the generic V1AuthRefresh builder with application/json body
func NewV1AuthRefreshRequest(server string, body V1AuthRefreshJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewV1AuthRefreshRequestWithBody(server, "application/json", bodyReader)
}

// NewV1AuthRefreshRequestWithBody generates requests for V1AuthRefresh with any type of body
func NewV1AuthRefreshRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/auth/refresh")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewV1AuthSignInRequest calls the generic V1AuthSignIn builder with application/json body
func NewV1AuthSignInRequest(server string, body V1AuthSignInJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewV1AuthSignInRequestWithBody(server, "application/json", bodyReader)
}

// NewV1AuthSignInRequestWithBody generates requests for V1AuthSignIn with any type of body
func NewV1AuthSignInRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/auth/signin")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewV1AuthSignOutRequest generates requests for V1AuthSignOut
func NewV1AuthSignOutRequest(server string) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/auth/signout")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewV1AuthSignUpRequest calls the generic V1AuthSignUp builder with application/json body
func NewV1AuthSignUpRequest(server string, body V1AuthSignUpJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewV1AuthSignUpRequestWithBody(server, "application/json", bodyReader)
}

// NewV1AuthSignUpRequestWithBody generates requests for V1AuthSignUp with any type of body
func NewV1AuthSignUpRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/auth/signup")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewV1AuthVerifyRequest generates requests for V1AuthVerify
func NewV1AuthVerifyRequest(server string) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/auth/verify")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func (c *Client) applyEditors(ctx context.Context, req *http.Request, additionalEditors []RequestEditorFn) error {
	for _, r := range c.RequestEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	for _, r := range additionalEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// ClientWithResponses builds on ClientInterface to offer response payloads
type ClientWithResponses struct {
	ClientInterface
}

// NewClientWithResponses creates a new ClientWithResponses, which wraps
// Client with return type handling
func NewClientWithResponses(server string, opts ...ClientOption) (*ClientWithResponses, error) {
	client, err := NewClient(server, opts...)
	if err != nil {
		return nil, err
	}
	return &ClientWithResponses{client}, nil
}

// WithBaseURL overrides the baseURL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) error {
		newBaseURL, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		c.Server = newBaseURL.String()
		return nil
	}
}

// ClientWithResponsesInterface is the interface specification for the client with responses above.
type ClientWithResponsesInterface interface {
	// V1AuthResign request with any body
	V1AuthResignWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*V1AuthResignResponse, error)

	V1AuthResignWithResponse(ctx context.Context, body V1AuthResignJSONRequestBody, reqEditors ...RequestEditorFn) (*V1AuthResignResponse, error)

	// V1AuthChangePassword request with any body
	V1AuthChangePasswordWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*V1AuthChangePasswordResponse, error)

	V1AuthChangePasswordWithResponse(ctx context.Context, body V1AuthChangePasswordJSONRequestBody, reqEditors ...RequestEditorFn) (*V1AuthChangePasswordResponse, error)

	// V1AuthRefresh request with any body
	V1AuthRefreshWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*V1AuthRefreshResponse, error)

	V1AuthRefreshWithResponse(ctx context.Context, body V1AuthRefreshJSONRequestBody, reqEditors ...RequestEditorFn) (*V1AuthRefreshResponse, error)

	// V1AuthSignIn request with any body
	V1AuthSignInWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*V1AuthSignInResponse, error)

	V1AuthSignInWithResponse(ctx context.Context, body V1AuthSignInJSONRequestBody, reqEditors ...RequestEditorFn) (*V1AuthSignInResponse, error)

	// V1AuthSignOut request
	V1AuthSignOutWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*V1AuthSignOutResponse, error)

	// V1AuthSignUp request with any body
	V1AuthSignUpWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*V1AuthSignUpResponse, error)

	V1AuthSignUpWithResponse(ctx context.Context, body V1AuthSignUpJSONRequestBody, reqEditors ...RequestEditorFn) (*V1AuthSignUpResponse, error)

	// V1AuthVerify request
	V1AuthVerifyWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*V1AuthVerifyResponse, error)
}

type V1AuthResignResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r V1AuthResignResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r V1AuthResignResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type V1AuthChangePasswordResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r V1AuthChangePasswordResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r V1AuthChangePasswordResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type V1AuthRefreshResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *V1AuthRefreshResponseSchema
}

// Status returns HTTPResponse.Status
func (r V1AuthRefreshResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r V1AuthRefreshResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type V1AuthSignInResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *V1AuthSignInResponseSchema
}

// Status returns HTTPResponse.Status
func (r V1AuthSignInResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r V1AuthSignInResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type V1AuthSignOutResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r V1AuthSignOutResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r V1AuthSignOutResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type V1AuthSignUpResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r V1AuthSignUpResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r V1AuthSignUpResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type V1AuthVerifyResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r V1AuthVerifyResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r V1AuthVerifyResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// V1AuthResignWithBodyWithResponse request with arbitrary body returning *V1AuthResignResponse
func (c *ClientWithResponses) V1AuthResignWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*V1AuthResignResponse, error) {
	rsp, err := c.V1AuthResignWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseV1AuthResignResponse(rsp)
}

func (c *ClientWithResponses) V1AuthResignWithResponse(ctx context.Context, body V1AuthResignJSONRequestBody, reqEditors ...RequestEditorFn) (*V1AuthResignResponse, error) {
	rsp, err := c.V1AuthResign(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseV1AuthResignResponse(rsp)
}

// V1AuthChangePasswordWithBodyWithResponse request with arbitrary body returning *V1AuthChangePasswordResponse
func (c *ClientWithResponses) V1AuthChangePasswordWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*V1AuthChangePasswordResponse, error) {
	rsp, err := c.V1AuthChangePasswordWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseV1AuthChangePasswordResponse(rsp)
}

func (c *ClientWithResponses) V1AuthChangePasswordWithResponse(ctx context.Context, body V1AuthChangePasswordJSONRequestBody, reqEditors ...RequestEditorFn) (*V1AuthChangePasswordResponse, error) {
	rsp, err := c.V1AuthChangePassword(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseV1AuthChangePasswordResponse(rsp)
}

// V1AuthRefreshWithBodyWithResponse request with arbitrary body returning *V1AuthRefreshResponse
func (c *ClientWithResponses) V1AuthRefreshWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*V1AuthRefreshResponse, error) {
	rsp, err := c.V1AuthRefreshWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseV1AuthRefreshResponse(rsp)
}

func (c *ClientWithResponses) V1AuthRefreshWithResponse(ctx context.Context, body V1AuthRefreshJSONRequestBody, reqEditors ...RequestEditorFn) (*V1AuthRefreshResponse, error) {
	rsp, err := c.V1AuthRefresh(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseV1AuthRefreshResponse(rsp)
}

// V1AuthSignInWithBodyWithResponse request with arbitrary body returning *V1AuthSignInResponse
func (c *ClientWithResponses) V1AuthSignInWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*V1AuthSignInResponse, error) {
	rsp, err := c.V1AuthSignInWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseV1AuthSignInResponse(rsp)
}

func (c *ClientWithResponses) V1AuthSignInWithResponse(ctx context.Context, body V1AuthSignInJSONRequestBody, reqEditors ...RequestEditorFn) (*V1AuthSignInResponse, error) {
	rsp, err := c.V1AuthSignIn(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseV1AuthSignInResponse(rsp)
}

// V1AuthSignOutWithResponse request returning *V1AuthSignOutResponse
func (c *ClientWithResponses) V1AuthSignOutWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*V1AuthSignOutResponse, error) {
	rsp, err := c.V1AuthSignOut(ctx, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseV1AuthSignOutResponse(rsp)
}

// V1AuthSignUpWithBodyWithResponse request with arbitrary body returning *V1AuthSignUpResponse
func (c *ClientWithResponses) V1AuthSignUpWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*V1AuthSignUpResponse, error) {
	rsp, err := c.V1AuthSignUpWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseV1AuthSignUpResponse(rsp)
}

func (c *ClientWithResponses) V1AuthSignUpWithResponse(ctx context.Context, body V1AuthSignUpJSONRequestBody, reqEditors ...RequestEditorFn) (*V1AuthSignUpResponse, error) {
	rsp, err := c.V1AuthSignUp(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseV1AuthSignUpResponse(rsp)
}

// V1AuthVerifyWithResponse request returning *V1AuthVerifyResponse
func (c *ClientWithResponses) V1AuthVerifyWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*V1AuthVerifyResponse, error) {
	rsp, err := c.V1AuthVerify(ctx, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseV1AuthVerifyResponse(rsp)
}

// ParseV1AuthResignResponse parses an HTTP response from a V1AuthResignWithResponse call
func ParseV1AuthResignResponse(rsp *http.Response) (*V1AuthResignResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &V1AuthResignResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ParseV1AuthChangePasswordResponse parses an HTTP response from a V1AuthChangePasswordWithResponse call
func ParseV1AuthChangePasswordResponse(rsp *http.Response) (*V1AuthChangePasswordResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &V1AuthChangePasswordResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ParseV1AuthRefreshResponse parses an HTTP response from a V1AuthRefreshWithResponse call
func ParseV1AuthRefreshResponse(rsp *http.Response) (*V1AuthRefreshResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &V1AuthRefreshResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest V1AuthRefreshResponseSchema
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	}

	return response, nil
}

// ParseV1AuthSignInResponse parses an HTTP response from a V1AuthSignInWithResponse call
func ParseV1AuthSignInResponse(rsp *http.Response) (*V1AuthSignInResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &V1AuthSignInResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest V1AuthSignInResponseSchema
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	}

	return response, nil
}

// ParseV1AuthSignOutResponse parses an HTTP response from a V1AuthSignOutWithResponse call
func ParseV1AuthSignOutResponse(rsp *http.Response) (*V1AuthSignOutResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &V1AuthSignOutResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ParseV1AuthSignUpResponse parses an HTTP response from a V1AuthSignUpWithResponse call
func ParseV1AuthSignUpResponse(rsp *http.Response) (*V1AuthSignUpResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &V1AuthSignUpResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ParseV1AuthVerifyResponse parses an HTTP response from a V1AuthVerifyWithResponse call
func ParseV1AuthVerifyResponse(rsp *http.Response) (*V1AuthVerifyResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &V1AuthVerifyResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}
