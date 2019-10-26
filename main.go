package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
)

type ApproleLoginPayload struct {
	RoleID   string `json:"role_id"`
	SecretID string `json:"secret_id"`
}

func auth(loginURL, roleID, secretID string) (string, error) {
	payload := &ApproleLoginPayload{RoleID: roleID, SecretID: secretID}
	payloadBuf := new(bytes.Buffer)
	err := json.NewEncoder(payloadBuf).Encode(payload)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(loginURL, "application/json", payloadBuf)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Unexpected HTTP status code: %s", resp.Status)
	}

	var result map[string]interface{}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	auth, ok := result["auth"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("Required key (auth) is not present in the response")
	}

	token, ok := auth["client_token"].(string)
	if !ok {
		return "", fmt.Errorf("Required key (auth.client_token) is not present on the response")
	}

	return token, nil
}

func main() {
	var address, roleID, secretID, output string

	flag.StringVar(&address, "address", os.Getenv("VAULT_ADDR"),
		"Address of vault server, VAULT_ADDR can be used instead")
	flag.StringVar(&roleID, "role_id", os.Getenv("VAULT_ROLE_ID"),
		"Role ID to use for login, VAULT_ROLE_ID can be used instead")
	flag.StringVar(&secretID, "secret_id", os.Getenv("VAULT_SECRET_ID"),
		"Secret ID to use for login, VAULT_SECRET_ID can be used instead")
	flag.StringVar(&output, "output", "", "Path to write the token")
	flag.Parse()

	if address == "" {
		fmt.Fprintln(os.Stderr, "Address of vault server is needed")
		os.Exit(-1)
	}
	if roleID == "" {
		fmt.Fprintln(os.Stderr, "Role ID is needed")
		os.Exit(-1)
	}
	if secretID == "" {
		fmt.Fprintln(os.Stderr, "Secret ID is needed")
		os.Exit(-1)
	}

	loginURL, err := url.Parse(address)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	loginURL.Path = path.Join(loginURL.Path, "/v1/auth/approle/login")

	token, err := auth(loginURL.String(), roleID, secretID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	var f *os.File
	if output != "" {
		f, err = os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	} else {
		f = os.Stdout
	}

	fmt.Fprintf(f, "%s\n", token)
}
