package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
	chat "google.golang.org/api/chat/v1"
)

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

func main() {
	r := gin.New()
	r.Use(RequestLogger())
	r.POST("/", cool_init, cool)
	r.Run()
}
