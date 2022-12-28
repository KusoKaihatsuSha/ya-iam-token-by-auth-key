package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
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
		Audience:  []string{"https://iam.api.cloud.yandex.net/iam/v1/tokens"},
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

func parseKeys() Key {
	key := Key{}
	file, err := os.ReadFile("authorized_key.json")
	if err != nil {
		fmt.Errorf("not found 'authorized_key.json' file in same directory: %w", err)
		panic(err)
	}
	err = json.Unmarshal(file, &key)
	if err != nil {
		panic(err)
	}
	return key
}

func getIAMToken() string {
	jot := signedToken(parseKeys())
	resp, err := http.Post(
		"https://iam.api.cloud.yandex.net/iam/v1/tokens",
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
	export := false
	save := true
	iam := getIAMToken()
	flag.BoolVar(&export, "export", false, "use flag for export to ENV")
	flag.BoolVar(&save, "save", true, "use flag for saving to file")
	flag.Parse()
	if export {
		os.Setenv("YC_TOKEN", iam)
		fmt.Printf("exported success \n\nexport YC_TOKEN=%s\n\n", iam)
	} else {
		fmt.Printf("use text below for ctrl+c --> ctrl+v \n\nexport YC_TOKEN=%s\n\n", iam)
	}
	if save {
		err := ioutil.WriteFile("IAM_token_output.txt", []byte(iam), 755)
		if err != nil {
			fmt.Errorf("error file save: %w\n\n", err)
			return
		}
		fmt.Println("IAM token save to **IAM_token_output.txt**")
	}

}
