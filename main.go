package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	dialogflow "cloud.google.com/go/dialogflow/apiv2"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/jsonq"
	chat "google.golang.org/api/chat/v1"
	dialogflowpb "google.golang.org/genproto/googleapis/cloud/dialogflow/v2"
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
func getServiceAccountKeyFileName() string {
	fileName := "/tmp/service-account-key.json"
	err := createServiceAccountKeyFile(fileName)
	fmt.Println(err)
	return fileName
}

func createServiceAccountKeyFile(fileName string) error {
	keyContents, err := base64.StdEncoding.DecodeString(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
	// fmt.Println(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
	if err != nil {
		return fmt.Errorf("error in base64 decoding service account key %s", err)
	}

	file, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("error in creating service account key file %s", err)
	}
	_, err = file.Write(keyContents)
	if err != nil {
		return fmt.Errorf("error in writing service account key file %s", err)
	}
	defer file.Close()
	return nil
}

func DetectIntentText(projectID, sessionID, text, languageCode string) (string, error) {
	ctx := context.Background()

	sessionClient, err := dialogflow.NewSessionsClient(ctx)
	if err != nil {
		return "", err
	}
	defer sessionClient.Close()

	if projectID == "" || sessionID == "" {
		return "", errors.New(fmt.Sprintf("Received empty project (%s) or session (%s)", projectID, sessionID))
	}

	sessionPath := fmt.Sprintf("projects/%s/agent/sessions/%s", projectID, sessionID)
	textInput := dialogflowpb.TextInput{Text: text, LanguageCode: languageCode}
	queryTextInput := dialogflowpb.QueryInput_Text{Text: &textInput}
	queryInput := dialogflowpb.QueryInput{Input: &queryTextInput}
	request := dialogflowpb.DetectIntentRequest{Session: sessionPath, QueryInput: &queryInput}

	response, err := sessionClient.DetectIntent(ctx, &request)
	if err != nil {
		return "", err
	}

	queryResult := response.GetQueryResult()
	fulfillmentText := queryResult.GetFulfillmentText()
	return fulfillmentText, nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func main() {
	//getServiceAccountKeyFileName()
	// r := gin.New()
	// r.Use(RequestLogger())
	// r.POST("/", cool_init, cool)
	// r.Run()
	// fmt.Println(string(requestJson()))

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -project-id <PROJECT ID> -session-id <SESSION ID> -language-code <LANGUAGE CODE> <OPERATION> <INPUTS>\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "<PROJECT ID> must be your Google Cloud Platform project id\n")
		fmt.Fprintf(os.Stderr, "<SESSION ID> must be a Dialogflow session ID\n")
		fmt.Fprintf(os.Stderr, "<LANGUAGE CODE> must be a language code from https://dialogflow.com/docs/reference/language; defaults to en\n")
		fmt.Fprintf(os.Stderr, "<OPERATION> must be one of text, audio, stream\n")
		fmt.Fprintf(os.Stderr, "<INPUTS> can be a series of text inputs if <OPERATION> is text, or a path to an audio file if <OPERATION> is audio or stream\n")
	}

	var projectID, sessionID, languageCode string
	flag.StringVar(&projectID, "project-id", "", "Google Cloud Platform project ID")
	//flag.StringVar(&sessionID, "session-id", "", "Dialogflow session ID")
	flag.StringVar(&languageCode, "language-code", "en", "Dialogflow language code from https://dialogflow.com/docs/reference/language; defaults to en")
	sessionID = RandStringRunes(36)
	flag.Parse()

	args := flag.Args()

	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	//operation := args[0]
	inputs := args[1:]

	fmt.Printf("Responses:\n")
	for _, query := range inputs {
		fmt.Printf("\nInput: %s\n", query)
		response, err := DetectIntentText(projectID, sessionID, query, languageCode)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Output: %s\n", response)
	}

}
