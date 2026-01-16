package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "valid API key with correct format",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-api-key-12345"},
			},
			expectedKey:   "my-secret-api-key-12345",
			expectedError: nil,
		},
		{
			name:          "missing Authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed Authorization header - wrong scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer my-token"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "malformed Authorization header - only ApiKey without value",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "empty Authorization header value",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)

			// Check the API key
			if apiKey != tt.expectedKey {
				t.Errorf("GetAPIKey() apiKey = %v, want %v", apiKey, tt.expectedKey)
			}

			// Check the error
			if tt.expectedError != nil && err == nil {
				t.Errorf("GetAPIKey() error = nil, want %v", tt.expectedError)
			}
			if tt.expectedError == nil && err != nil {
				t.Errorf("GetAPIKey() error = %v, want nil", err)
			}
			if tt.expectedError != nil && err != nil && err.Error() != tt.expectedError.Error() {
				t.Errorf("GetAPIKey() error = %v, want %v", err, tt.expectedError)
			}
		})
	}
}
