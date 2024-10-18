package gopos

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
)

// TokenResponse struct for unmarshalling the JSON response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

// GetToken retrieves an access token from GoPos using the provided credentials.
func GetTokenGoPos(goPosURL, clientID, clientSecret, email, password string) (string, error) {
	// Form the request data
	data := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"grant_type":    {"password"},
		"username":      {email},
		"password":      {password},
	}

	// Send the POST request
	resp, err := http.PostForm(goPosURL+"/oauth/token", data)
	if err != nil {
		return "", fmt.Errorf("failed to make POST request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for a non-2xx status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("Non-2xx response: %s", resp.Status)
		return "", errors.New("received non-2xx response from GoPos")
	}

	// Unmarshal the response into the TokenResponse struct
	var tokenResponse TokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	return tokenResponse.AccessToken, nil
}
