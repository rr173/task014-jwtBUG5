package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestVerifyExpiredTokenReturnsClaims verifies that the /verify endpoint
// includes decoded claims in the response even when the token is expired.
// This allows clients to inspect who the token belongs to without requiring
// a separate decode step.
func TestVerifyExpiredTokenReturnsClaims(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	secret := []byte("test-secret")
	api := NewWithClock(secret, 0, func() time.Time { return now })
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	// Sign a token that expired 100 seconds ago
	signBody, _ := json.Marshal(map[string]any{"claims": map[string]any{
		"sub": "alice",
		"iss": "test-issuer",
		"exp": now.Unix() - 100,
	}})
	signResp, err := http.DefaultClient.Post(srv.URL+"/sign", "application/json", bytes.NewReader(signBody))
	if err != nil {
		t.Fatal(err)
	}
	signData, _ := io.ReadAll(signResp.Body)
	signResp.Body.Close()

	var signOut struct{ Token string }
	json.Unmarshal(signData, &signOut)
	if signOut.Token == "" {
		t.Fatal("failed to sign token")
	}

	// Verify the expired token
	verifyBody, _ := json.Marshal(map[string]any{"token": signOut.Token})
	verifyResp, err := http.DefaultClient.Post(srv.URL+"/verify", "application/json", bytes.NewReader(verifyBody))
	if err != nil {
		t.Fatal(err)
	}
	verifyData, _ := io.ReadAll(verifyResp.Body)
	verifyResp.Body.Close()

	var out struct {
		Valid  bool           `json:"valid"`
		Error  string         `json:"error"`
		Claims map[string]any `json:"claims"`
	}
	if err := json.Unmarshal(verifyData, &out); err != nil {
		t.Fatal(err)
	}

	// Token should be invalid (expired)
	if out.Valid {
		t.Fatalf("expired token should not be valid")
	}
	// But claims should still be present in the response
	if out.Claims == nil {
		t.Fatalf("expired token response should include claims, got nil")
	}
	if out.Claims["sub"] != "alice" {
		t.Fatalf("claims[sub] should be alice, got %v", out.Claims["sub"])
	}
	if out.Claims["iss"] != "test-issuer" {
		t.Fatalf("claims[iss] should be test-issuer, got %v", out.Claims["iss"])
	}
}

// TestVerifyNotYetValidTokenReturnsClaims verifies claims are returned
// for tokens that haven't become valid yet.
func TestVerifyNotYetValidTokenReturnsClaims(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	secret := []byte("test-secret")
	api := NewWithClock(secret, 0, func() time.Time { return now })
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	// Sign a token that is not yet valid (nbf in the future)
	signBody, _ := json.Marshal(map[string]any{"claims": map[string]any{
		"sub": "bob",
		"nbf": now.Unix() + 3600,
	}})
	signResp, _ := http.DefaultClient.Post(srv.URL+"/sign", "application/json", bytes.NewReader(signBody))
	signData, _ := io.ReadAll(signResp.Body)
	signResp.Body.Close()

	var signOut struct{ Token string }
	json.Unmarshal(signData, &signOut)

	verifyBody, _ := json.Marshal(map[string]any{"token": signOut.Token})
	verifyResp, _ := http.DefaultClient.Post(srv.URL+"/verify", "application/json", bytes.NewReader(verifyBody))
	verifyData, _ := io.ReadAll(verifyResp.Body)
	verifyResp.Body.Close()

	var out struct {
		Valid  bool           `json:"valid"`
		Error  string         `json:"error"`
		Claims map[string]any `json:"claims"`
	}
	json.Unmarshal(verifyData, &out)

	if out.Valid {
		t.Fatalf("not-yet-valid token should not be valid")
	}
	if out.Claims == nil {
		t.Fatalf("not-yet-valid token response should include claims, got nil")
	}
	if out.Claims["sub"] != "bob" {
		t.Fatalf("claims[sub] should be bob, got %v", out.Claims["sub"])
	}
}
