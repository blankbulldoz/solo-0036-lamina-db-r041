package engine

import (
	"errors"
	"fmt"
	"lamina/internal/reach"
)

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Message }

func fault(code, format string, args ...any) error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}
func invalid(err error) error {
	if err == nil {
		return nil
	}
	return fault("invalid", "%s", err)
}

// reachFault preserves the code assigned by the shared reachability
// package so precheck and live endpoints report identical failures.
func reachFault(err error) error {
	if err == nil {
		return nil
	}
	var re *reach.Error
	if errors.As(err, &re) {
		return &Error{Code: re.Code, Message: re.Message}
	}
	return err
}
