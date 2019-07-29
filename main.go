package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/jsonq"
	chat "google.golang.org/api/chat/v1"
)

var token string

const jwksURL = `https://www.googleapis.com/service_accounts/v1/metadata/x509/chat@system.gserviceaccount.com`

var myClient = &http.Client{Timeout: 10 * time.Second}

func requestJson() []byte {
	resp, err := http.Get(jwksURL)
	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	//log.Println(string(body))
	return body
}

func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {

		reqToken := c.Request.Header.Get("Authorization")
		splitToken := strings.Split(reqToken, "Bearer")
		reqToken = strings.TrimSpace(splitToken[1])
		token = reqToken
		tk, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
			keyID, ok := t.Header["kid"].(string)
			if !ok {
				return nil, errors.New("expecting JWT header to have string kid")
			}
			data := map[string]interface{}{}
			dec := json.NewDecoder(strings.NewReader(string(requestJson())))
			dec.Decode(&data)
			jq := jsonq.NewQuery(data)
			cert, _ := jq.String(keyID)
			return ParseRSAPublicKeyFromPEM([]byte(cert))
		})

		if tk.Valid {
			fmt.Println("Valid")
		} else {
			fmt.Print(err)
		}

		c.Next()
	}
}
func cool_init(c *gin.Context) {

	c.Set("example", "Bye..!")
	c.Next()
}

func cool(c *gin.Context) {
	var json chat.DeprecatedEvent
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	switch json.Type {
	case "ADDED_TO_SPACE":
		c.JSON(200, gin.H{
			"text": "thanks for adding me.",
		})
	case "MESSAGE":
		c.JSON(200, gin.H{
			"text": "hey dude how are you   " + c.MustGet("example").(string),
		})
	}
}

func ParseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, nil
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	var pkey *rsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, err
	}
	return pkey, nil
}
func main() {

	r := gin.New()
	r.Use(RequestLogger())
	r.POST("/", cool_init, cool)
	r.Run()
	fmt.Println(string(requestJson()))

}
