package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	chat "google.golang.org/api/chat/v1"
)

func GetWeapons(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fmt.Fprint(w, "not allowed")
		return
	}
	var event chat.DeprecatedEvent

	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	switch event.Type {
	case "ADDED_TO_SPACE":
		if event.Space.Type != "ROOM" {
			break
		}
		fmt.Fprint(w, `{"text":"thanks for adding me."}`)
	case "MESSAGE":
		fmt.Fprintf(w, `{"text":"you said %s"}`, event.Message.Text)
	}
}

func cool(c *gin.Context) {
	c.JSON(200, gin.H{
		"text": "hello",
	})
}

func main() {
	r := gin.Default()
	r.POST("/", cool)
	r.Run()
}
