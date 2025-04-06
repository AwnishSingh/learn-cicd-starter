package auth

import (
	"net/http"
	"testing"

	"errors"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		header        http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "Valid API Key",
			header:        http.Header{"Authorization": []string{"ApiKey 1234567890"}},
			expectedKey:   "1234567890",
			expectedError: nil,
		},
		{
			name:          "Missing Authorization Header",
			header:        http.Header{},
			expectedKey:   "",
			expectedError: errors.New("no authorization header included"),
		},
		{
			name:          "Malformed Authorization Header",
			header:        http.Header{"Authorization": []string{"InvalidFormat"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Wrong Auth Type",
			header:        http.Header{"Authorization": []string{"Bearer 1234567890"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := auth.GetAPIKey(tt.header)

			if tt.expectedError != nil {
				if err == nil {
					t.Fatalf("Expected error %v, got nil", tt.expectedError)
				}
				if err.Error() != tt.expectedError.Error() {
					t.Fatalf("Expected error %v, got %v", tt.expectedError, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}
			if apiKey != tt.expectedKey {
				t.Fatalf("Expected API key %v, got %v", tt.expectedKey, apiKey)
			}
		})
	}
}
