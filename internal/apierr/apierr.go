// Package apierr writes the proxy error body SDKs already know how to show.
package apierr

import (
	"encoding/json"
	"net/http"
)

type body struct {
	Error struct {
		Type    string `json:"type"`
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Write sets X-Keman-Error and an OpenAI-shaped JSON body.
func Write(w http.ResponseWriter, status int, code, message string) {
	var b body
	b.Error.Type = "keman_error"
	b.Error.Code = code
	b.Error.Message = message
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Keman-Error", code)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(b)
}

// Status is the HTTP status for a proxy error code.
func Status(code string) int {
	switch code {
	case "invalid_key", "key_disabled", "key_revoked", "key_expired":
		return http.StatusUnauthorized
	case "path_not_allowed", "model_not_allowed", "network_not_allowed",
		"spend_cap_reached", "unknown_model_price":
		return http.StatusForbidden
	case "rate_limited":
		return http.StatusTooManyRequests
	case "upstream_redirect_blocked", "upstream_unavailable":
		return http.StatusBadGateway
	case "store_unavailable":
		return http.StatusServiceUnavailable
	case "request_too_large":
		return http.StatusRequestEntityTooLarge
	default:
		return http.StatusBadRequest
	}
}

// Message is the stable sentence for a code.
func Message(code string) string {
	switch code {
	case "invalid_key":
		return "The virtual key is invalid."
	case "key_disabled":
		return "This virtual key is disabled."
	case "key_revoked":
		return "This virtual key has been revoked."
	case "key_expired":
		return "This virtual key has expired."
	case "path_not_allowed":
		return "This path is not allowed for this virtual key."
	case "model_not_allowed":
		return "This model is not allowed for this virtual key."
	case "network_not_allowed":
		return "This client network is not allowed for this virtual key."
	case "spend_cap_reached":
		return "This virtual key has reached its spend cap."
	case "unknown_model_price":
		return "This model has no price, so a spend cap cannot be enforced."
	case "rate_limited":
		return "Too many requests."
	case "upstream_redirect_blocked":
		return "The upstream redirect was blocked."
	case "upstream_unavailable":
		return "The upstream request failed."
	case "store_unavailable":
		return "Spend state is unavailable."
	case "request_too_large":
		return "The request body is too large."
	default:
		return "The request was rejected."
	}
}

// Fail writes the status, header, and message for code.
func Fail(w http.ResponseWriter, code string) {
	Write(w, Status(code), code, Message(code))
}
