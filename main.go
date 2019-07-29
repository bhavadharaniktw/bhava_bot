package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/jsonq"
	"github.com/lestrrat/go-jwx/jwk"
	chat "google.golang.org/api/chat/v1"
)

const token = `eyJhbGciOiJSUzI1NiIsImtpZCI6ImMxZWY3YTYwZmMxYzgyZmEyZjY3ZDMzNTlmZTc0OWZkMmMzMmJjMzciLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiI3NDcwNjEzNjY3MiIsImV4cCI6MTU2NDM4MTc1OCwiaWF0IjoxNTY0Mzc4MTU4LCJpc3MiOiJjaGF0QHN5c3RlbS5nc2VydmljZWFjY291bnQuY29tIn0.JZqLmNWtshdv9siiPaRfcKd_9-59Cir1B8kAldeIhOUBkcH711Mib6VutrUd6xWubdm-2F6wV2z_CvqQzBL5Qq99_tqy6OWEWdh2cbEr3SwZVt4rmn9p5ZFlYanGaHaixI4KduP7cgBrPOqdtNDuYFRPB7DhosUFsgieVNtDqQ08w2Pw3BENR92rm1WJSG5dVVC78SW-NiKz3OafNJ-IiObtCnCp_IofKl02rdN5jc6r6pLACgnA_kk0Bjp6wwKPax0ceFEihu1090-T-5Q4iM9mISWH2dJu_4jrezLX8OBPQl0gFyiItDjPk80zd8uHNRD51WPy2IKsGNz15oIvcg`

const jwksURL = `https://www.googleapis.com/service_accounts/v1/metadata/x509/chat@system.gserviceaccount.com`

var myClient = &http.Client{Timeout: 10 * time.Second}

func getJson(url string, target interface{}) error {
	r, err := myClient.Get(url)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	return json.NewDecoder(r.Body).Decode(target)
}
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
func getKey(token *jwt.Token) (interface{}, error) {

	set, err := jwk.FetchHTTP(jwksURL)

	fmt.Println("Set:")
	fmt.Println(set)

	if err != nil {
		return nil, err
	}

	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}

	if key := set.LookupKeyID(keyID); len(key) == 1 {
		return key[0].Materialize()
	}

	return nil, errors.New("unable to find key")
}

func authenticator() {

}

func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		body_buff, _ := ioutil.ReadAll(c.Request.Body)
		rdr1 := ioutil.NopCloser(bytes.NewBuffer(body_buff))
		rdr2 := ioutil.NopCloser(bytes.NewBuffer(body_buff)) //We have to create a new Buffer, because rdr1 will be read.

		fmt.Println(readBody(rdr1)) // Print request body

		c.Request.Body = rdr2
		fmt.Println("\nHeader:\n")
		fmt.Println(c.Request.Header)
		c.Next()
	}
}

func readBody(reader io.Reader) string {
	buf := new(bytes.Buffer)
	buf.ReadFrom(reader)

	s := buf.String()
	return s
}

func cool_init(c *gin.Context) {

	// Set example variable
	c.Set("example", "12345")

	// before request

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
			"text": "thanks for adding me." + c.MustGet("example").(string),
		})
	}
}

type Foo struct {
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
	// token, err := jwt.Parse(token, getKey)
	// if err != nil {
	// 	panic(err)
	// }
	// claims := token.Claims.(jwt.MapClaims)
	// for key, value := range claims {
	// 	fmt.Printf("%s\t%v\n", key, value)
	// }
	fmt.Println(string(requestJson()))
	tk, err := jwt.Parse(token, keyFunc)
	fmt.Println(tk)
	if tk.Valid {
		fmt.Println(" The token is Valid")
	} else {
		fmt.Print(err)
	}

	// r := gin.New()
	// r.Use(RequestLogger())
	// r.POST("/", cool_init, cool)
	// r.Run()
}

func keyFunc(t *jwt.Token) (interface{}, error) {
	
	keyID, ok := t.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}
	//fmt.Println(keyID)
	data := map[string]interface{}{}
	dec := json.NewDecoder(strings.NewReader(string(requestJson())))
	dec.Decode(&data)
	jq := jsonq.NewQuery(data)
	cert, _ := jq.String(keyID)
	fmt.Println(cert)
	return ParseRSAPublicKeyFromPEM([]byte(cert))
	//return []byte(cert), nil
}