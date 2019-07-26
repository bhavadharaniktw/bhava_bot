package main

import (
	"bytes"
	"encoding/json"
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

const token = `eyJhbGciOiJSUzI1NiIsImtpZCI6ImFlZjQ4ZjAyODNkNTc2YjhkZTg0NDMyMTcyNDhlOTMxOTRjODNjOTQiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiI3NDcwNjEzNjY3MiIsImV4cCI6MTU2NDAzOTk2MywiaWF0IjoxNTY0MDM2MzYzLCJpc3MiOiJjaGF0QHN5c3RlbS5nc2VydmljZWFjY291bnQuY29tIn0.OZEGaAM0nday9W-DDLl9WZUQPZfFnu3qbZShJIBBgvnXwR_uhsnbRy7ycR38iBnzkMfVsQk0Xye5Yg-rZ2eNoXJnvUj5tAwC043D2lEZvS7MTUUkSTY3RvahY9HxS4dmXu1qGim4nhDINwjAk_yyi2yCiKwjKdnw1Oe2KNYTLXJZnVVAS17aYF_vxSaSs81PNKsroPvfTCeCuyffBITWidrtpI3pvwGO31_No_nBFCOfDDuNB9y_uZG8cCAD3SBinzUPtLoIEC8QbYhZLN58oynkvMlCTsVNyJhdtR5qKGUmO2Y0DxduSm1o8qJ5mQxR_BiiNCScoeEgMskz63UsRQ`

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
	tk, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		keyID, ok := t.Header["kid"].(string)
		if !ok {
			return nil, errors.New("expecting JWT header to have string kid")
		}
		//fmt.Println(keyID)
		data := map[string]interface{}{}
		dec := json.NewDecoder(strings.NewReader(string(requestJson())))
		dec.Decode(&data)
		jq := jsonq.NewQuery(data)
		cert, err := jq.String(keyID)
		fmt.Println(err)
		return []byte(cert), nil
	})
	fmt.Println(tk.Valid)
	if tk.Valid {
		fmt.Println("Valid")
	} else {
		fmt.Print(err)
	}
	// fmt.Println(tok)
	// fmt.Println(err)
	// r := gin.New()
	// r.Use(RequestLogger())
	// r.POST("/", cool_init, cool)
	// r.Run()
}
