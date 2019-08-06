package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	// "github.com/apex/up/platform/lambda"

	dialogflow "cloud.google.com/go/dialogflow/apiv2"
	// "github.com/apex/gateway"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	ginadapter "github.com/awslabs/aws-lambda-go-api-proxy/gin"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/jsonq"
	"google.golang.org/api/chat/v1"
	"google.golang.org/api/option"
	dialogflowpb "google.golang.org/genproto/googleapis/cloud/dialogflow/v2"
)

var token string

const jwksURL = `https://www.googleapis.com/service_accounts/v1/metadata/x509/chat@system.gserviceaccount.com`

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randomStringGenerator(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func getCertificateJSONFromURL(URL string) []byte {
	resp, err := http.Get(URL)
	fmt.Println("================= certificate error ===========")
	fmt.Println(err)
	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	fmt.Println("================certificate resp body error ===========")
	fmt.Println(err)
	if err != nil {
		log.Fatalln(err)
	}
	return body
}

func authorizeHangoutsClient(c *gin.Context) {
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
		dec := json.NewDecoder(strings.NewReader(string(getCertificateJSONFromURL(jwksURL))))
		dec.Decode(&data)
		jq := jsonq.NewQuery(data)
		cert, _ := jq.String(keyID)
		return parseRSAPublicKeyFromPEM([]byte(cert))
	})
	fmt.Println("================= authorization error ===========")
	fmt.Println(err)
	if tk.Valid && err == nil {
		c.Next()
	} else {
		c.AbortWithStatus(401)
	}
}
func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		bodyBuff, _ := ioutil.ReadAll(c.Request.Body)
		rdr1 := ioutil.NopCloser(bytes.NewBuffer(bodyBuff))
		rdr2 := ioutil.NopCloser(bytes.NewBuffer(bodyBuff)) //We have to create a new Buffer, because rdr1 will be read.
		//fmt.Println("\nBody:\n")
		fmt.Println(readBody(rdr1)) // Print request body

		c.Request.Body = rdr2
		//fmt.Println("\nHeader:\n")
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

func dialogflowRequestHandler(c *gin.Context) {
	var json chat.DeprecatedEvent
	if err := c.ShouldBindJSON(&json); err != nil {
		fmt.Println("================= dialogflow request handler error ===========")
		fmt.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	switch json.Type {
	case "ADDED_TO_SPACE":
		c.JSON(200, gin.H{
			"text": "Thanks for adding me.",
		})
	case "MESSAGE":
		response, respError := getResponseFromDialogflow(json.Message.Text)
		fmt.Println("=================dialogflow response error ===========")
		fmt.Println(respError)
		if respError != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": respError.Error()})
			return
		}
		c.JSON(200, gin.H{
			"text": response,
		})
	}
}

func getSessionID() string {
	return randomStringGenerator(36)
}

func getResponseFromDialogflow(userQuery string) (string, error) {
	response, err := detectIntentText("bhava-fbvvum", getSessionID(), userQuery, "en")
	if err != nil {
		return "", err
	}
	return response, nil
}

func detectIntentText(projectID, sessionID, text, languageCode string) (string, error) {
	ctx := context.Background()

	sessionClient, err := dialogflow.NewSessionsClient(ctx, option.WithCredentialsJSON(getCertificateJSONFromURL("https://bhavabucket.s3.us-east-2.amazonaws.com/service_acc_key_bhava_bot.json")))

	if err != nil {
		return "", err
	}
	defer sessionClient.Close()

	if projectID == "" || sessionID == "" {
		return "", fmt.Errorf("Received empty project (%s) or session (%s)", projectID, sessionID)
	}

	sessionPath := fmt.Sprintf("projects/%s/agent/sessions/%s", projectID, sessionID)
	textInput := dialogflowpb.TextInput{Text: text, LanguageCode: languageCode}
	queryTextInput := dialogflowpb.QueryInput_Text{Text: &textInput}
	queryInput := dialogflowpb.QueryInput{Input: &queryTextInput}
	request := dialogflowpb.DetectIntentRequest{Session: sessionPath, QueryInput: &queryInput}

	response, err := sessionClient.DetectIntent(ctx, &request)
	fmt.Println("================= detect intent resp error ===========")
	fmt.Println(err)
	if err != nil {
		return "", err
	}

	queryResult := response.GetQueryResult()
	fulfillmentText := queryResult.GetFulfillmentText()
	return fulfillmentText, nil
}

func parseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
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

func dummyHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"text": "The lambda is working",
	})
}

var initialized = false
var ginLambda *ginadapter.GinLambda

func Handler(req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	if !initialized {
		ginEngine := getRouterEngine()
		ginLambda = ginadapter.New(ginEngine)
		initialized = true
	}
	return ginLambda.Proxy(req)
}

func getRouterEngine() *gin.Engine {
	gin.SetMode(gin.DebugMode)
	r := gin.New()
	r.Use(requestLogger())
	r.GET("/", dummyHandler)
	r.POST("/", authorizeHangoutsClient, dialogflowRequestHandler)
	return r
}

func main() {
	//log.Fatal(gateway.ListenAndServe(":8080", Handler()))
	lambda.Start(Handler)

}
