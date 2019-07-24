package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	chat "google.golang.org/api/chat/v1"
)

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
			"text": "hello " + json.User.DisplayName + ", you replied with " + json.Message.Text,
		})
	}

}

func main() {
	r := gin.Default()
	r.POST("/", cool)
	r.Run()
}
