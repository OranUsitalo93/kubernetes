package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// UserInfo holds information about the authenticated user.
type UserInfo interface {
	GetName() string
	GetUID() string
	GetGroups() []string
	GetExtra() map[string][]string
}

// DefaultUserInfo is a simple implementation of UserInfo.
type DefaultUserInfo struct {
	Name   string
	UID    string
	Groups []string
	Extra  map[string][]string
}

func (u *DefaultUserInfo) GetName() string { return u.Name }
func (u *DefaultUserInfo) GetUID() string  { return u.UID }
func (u *DefaultUserInfo) GetGroups() []string { return u.Groups }
func (u *DefaultUserInfo) GetExtra() map[string][]string { return u.Extra }

// AuthenticateResponse holds the response of an authentication attempt.
type AuthenticateResponse struct {
	User UserInfo
	OK   bool
	Err  error
}

// Authenticator defines the interface for authenticating a request.
type Authenticator interface {
	AuthenticateRequest(req *http.Request) (*AuthenticateResponse, bool, error)
}

// StatusError is an interface for errors that carry an HTTP status code.
type StatusError interface {
	error
	Status() int
}

// AuthenticationError is a concrete implementation of StatusError.
type AuthenticationError struct {
	Message    string
	StatusCode int
	Headers    http.Header
}

func (e *AuthenticationError) Error() string {
	return e.Message
}

func (e *AuthenticationError) Status() int {
	return e.StatusCode
}

type contextKey int
const responseWriterKey contextKey = iota

// GetResponseWriter retrieves the StatusTrackingResponseWriter from the request context.
func GetResponseWriter(req *http.Request) http.ResponseWriter {
	if w, ok := req.Context().Value(responseWriterKey).(http.ResponseWriter); ok {
		return w
	}
	return nil
}

// UnionAuthenticator evaluates multiple authenticators sequentially.
type UnionAuthenticator struct {
	Authenticators []Authenticator
}

func NewUnionAuthenticator(authenticators ...Authenticator) *UnionAuthenticator {
	return &UnionAuthenticator{Authenticators: authenticators}
}

// AuthenticateRequest evaluates authenticators.
// If an authenticator returns an error, we aggregate it.
// If one succeeds, we return it.
func (u *UnionAuthenticator) AuthenticateRequest(req *http.Request) (*AuthenticateResponse, bool, error) {
	var errs []error
	for _, auth := range u.Authenticators {
		// Check if a failure status code has already been written to the response writer.
		if w := GetResponseWriter(req); w != nil {
			if tw, ok := w.(*StatusTrackingResponseWriter); ok && tw.WroteHeader() && tw.Status() >= 400 && tw.Status() < 600 {
				return nil, false, errors.New("authentication short-circuited due to prior failure status code")
			}
		}

		resp, ok, err := auth.AuthenticateRequest(req)
		if err != nil {
			errs = append(errs, err)
		}
		if ok {
			return resp, true, nil
		}

		// Check again after evaluating the authenticator.
		if w := GetResponseWriter(req); w != nil {
			if tw, ok := w.(*StatusTrackingResponseWriter); ok && tw.WroteHeader() && tw.Status() >= 400 && tw.Status() < 600 {
				return nil, false, errors.Join(errs...)
			}
		}
	}
	if len(errs) > 0 {
		return nil, false, errors.Join(errs...)
	}
	return nil, false, nil
}

// StatusTrackingResponseWriter wraps http.ResponseWriter to track status code and prevent overwriting failure codes.
type StatusTrackingResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func NewStatusTrackingResponseWriter(w http.ResponseWriter) *StatusTrackingResponseWriter {
	return &StatusTrackingResponseWriter{ResponseWriter: w}
}

func (w *StatusTrackingResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		if w.status >= 400 && w.status < 600 {
			return
		}
	}
	w.status = code
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *StatusTrackingResponseWriter) Write(b []byte) (int, error) {
	if w.wroteHeader && w.status >= 400 && w.status < 600 {
		return len(b), nil
	}
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *StatusTrackingResponseWriter) Status() int {
	if !w.wroteHeader {
		return http.StatusOK
	}
	return w.status
}

func (w *StatusTrackingResponseWriter) WroteHeader() bool {
	return w.wroteHeader
}

// AuthenticationMiddleware wraps the request handler with authentication logic.
type AuthenticationMiddleware struct {
	Authenticator    Authenticator
	FailedHandler    http.Handler
	Next             http.Handler
	AnonymousEnabled bool
	AnonymousUser    UserInfo
}

func (m *AuthenticationMiddleware) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	trackingWriter := NewStatusTrackingResponseWriter(w)

	ctx := context.WithValue(req.Context(), responseWriterKey, trackingWriter)
	req = req.WithContext(ctx)

	resp, ok, err := m.Authenticator.AuthenticateRequest(req)
	if err != nil {
		if trackingWriter.WroteHeader() && trackingWriter.Status() >= 400 && trackingWriter.Status() < 600 {
			return
		}

		var statusErr StatusError
		if errors.As(err, &statusErr) {
			if authErr, ok := err.(*AuthenticationError); ok && authErr.Headers != nil {
				for k, vs := range authErr.Headers {
					for _, v := range vs {
						trackingWriter.Header().Add(k, v)
					}
				}
			}
			trackingWriter.WriteHeader(statusErr.Status())
			trackingWriter.Write([]byte(err.Error()))
			return
		}

		m.FailedHandler.ServeHTTP(trackingWriter, req)
		return
	}

	if ok {
		if trackingWriter.WroteHeader() && trackingWriter.Status() >= 400 && trackingWriter.Status() < 600 {
			return
		}
		ctx = context.WithValue(req.Context(), "user", resp.User)
		m.Next.ServeHTTP(trackingWriter, req.WithContext(ctx))
		return
	}

	if m.AnonymousEnabled && m.AnonymousUser != nil {
		if trackingWriter.WroteHeader() && trackingWriter.Status() >= 400 && trackingWriter.Status() < 600 {
			return
		}
		ctx = context.WithValue(req.Context(), "user", m.AnonymousUser)
		m.Next.ServeHTTP(trackingWriter, req.WithContext(ctx))
		return
	}

	if trackingWriter.WroteHeader() && trackingWriter.Status() >= 400 && trackingWriter.Status() < 600 {
			return
	}
	m.FailedHandler.ServeHTTP(trackingWriter, req)
}

func main() {
	fmt.Println("Hello, Bounty Hunter!")
}
