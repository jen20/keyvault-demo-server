package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
)

func getKeyVaultToken() (string, error) {
	query := url.Values{}
	query.Add("api-version", "2018-02-01")
	query.Add("resource", "https://vault.azure.net")

	tokenURL := url.URL{
		Scheme:   "http",
		Host:     "169.254.169.254",
		Path:     path.Join("metadata", "identity", "oauth2", "token"),
		RawQuery: query.Encode(),
	}

	req, err := http.NewRequest(http.MethodGet, tokenURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Metadata", "true")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body := struct {
		AccessToken string `json:"access_token"`
	}{}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&body); err != nil {
		return "", err
	}

	return body.AccessToken, nil
}

func getSecret(secretName string, vaultName string, vaultToken string) (string, error) {
	query := url.Values{}
	query.Add("api-version", "2016-10-01")
	secretURL := url.URL{
		Scheme:   "https",
		Host:     fmt.Sprintf("%s.vault.azure.net", vaultName),
		Path:     path.Join("secrets", secretName),
		RawQuery: query.Encode(),
	}

	req, err := http.NewRequest(http.MethodGet, secretURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", vaultToken))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body := struct {
		Value string `json:"value"`
	}{}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&body); err != nil {
		return "", err
	}

	return body.Value, nil
}

func main() {
	if len(os.Args) != 3 {
		_, _ = fmt.Fprintf(os.Stderr, "USAGE: %s <KeyVault Name> <Secret Name>")
		os.Exit(1)
	}

	token, err := getKeyVaultToken()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error getting KeyVault Token: %s\n", err)
		os.Exit(1)
	}

	secret, err := getSecret(os.Args[2], os.Args[1], token)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error getting Secret: %s\n", err)
		os.Exit(1)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "Our secret is: \"%s\"!\n", secret)
	})

	log.Fatal(http.ListenAndServe(":80", nil))
}
