package main

import (
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
)

func GetWeapons(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println(string(body))
	fmt.Fprintf(w, "Hello, bhava")
}

func cool(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
}

func main() {
	http.HandleFunc("/", GetWeapons)

	http.ListenAndServe(":8080", nil)
}
