package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"

	chat "google.golang.org/api/chat/v1"
)

func GetWeapons(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
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

func cool(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
}

func main() {
	http.HandleFunc("/", GetWeapons)

	http.ListenAndServe(":8080", nil)
}
