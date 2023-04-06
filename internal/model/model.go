package model

import "errors"

type Token struct {
	IDToken      string
	RefreshToken string
}

type UnauthorizedError struct{}

func (ue UnauthorizedError) Error() string {
	return "unauthorized"
}

func AsUnauthorizedError(err error) bool {
	var target UnauthorizedError

	return errors.As(err, &target)
}
