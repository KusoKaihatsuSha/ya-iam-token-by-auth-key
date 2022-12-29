package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
)

const (
	audience = "https://iam.api.cloud.yandex.net/iam/v1/tokens"
	API      = "https://iam.api.cloud.yandex.net/iam/v1/tokens"
)

type Key struct {
	ID        string `json:"id"`
	AccountID string `json:"service_account_id"`
	Created   string `json:"created_at"`
	Algorithm string `json:"key_algorithm"`
	Public    string `json:"public_key"`
	Private   string `json:"private_key"`
}

func signedToken(k Key) string {
	claims := jwt.RegisteredClaims{
		Issuer:    k.AccountID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Audience:  []string{audience},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodPS256, claims)
	token.Header["kid"] = k.ID
	rsaPrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(k.Private))
	if err != nil {
		panic(err)
	}
	signed, err := token.SignedString(rsaPrivateKey)
	if err != nil {
		panic(err)
	}
	return signed
}

func parseKeys(loadPath string) Key {
	key := Key{}
	file, err := os.ReadFile(loadPath)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(file, &key)
	if err != nil {
		panic(err)
	}
	return key
}

func getIAMToken(loadPath string) string {
	jot := signedToken(parseKeys(loadPath))
	resp, err := http.Post(
		API,
		"application/json",
		strings.NewReader(fmt.Sprintf(`{"jwt":"%s"}`, jot)),
	)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		panic(fmt.Sprintf("%s: %s", resp.Status, body))
	}
	var data struct {
		IAMToken string `json:"iamToken"`
	}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		panic(err)
	}
	return data.IAMToken
}

func main() {
	raw := false
	tokenName, load, save := "", "", ""
	flag.StringVar(&tokenName, "token", "YC_TOKEN", "set token name")
	flag.BoolVar(&raw, "raw", false, "use flag for print without 'export' text. If 'false' you may use\n\n'eval $(app)'\n\nOR\n\nFor /f \"delims=\" %A in ('ya-iam-token-by-auth-key.exe') do call %A")
	flag.StringVar(&load, "from", "authorized_key.json", "use flag for set filepath with keys")
	flag.StringVar(&save, "to", "", "use flag for saving IAM to filepath. Example: 'IAM_token_output.txt'")
	flag.Parse()
	iam := getIAMToken(load)
	if raw {
		fmt.Printf("%s", iam)
	} else {
		if runtime.GOOS == "windows" {
			fmt.Printf("set %s=%s", tokenName, iam)
		} else {
			fmt.Printf("export %s=%s", tokenName, iam)
		}
	}
	if pathSave := strings.TrimSpace(save); pathSave != "" {
		err := ioutil.WriteFile(pathSave, []byte(iam), 755)
		if err != nil {
			log.Debug().Msgf("%v", err)
			return
		}
	}
}
