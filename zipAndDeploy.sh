#!/bin/sh

rm pizzahandler.zip
GOOS=linux go build pizzahandler.go
zip pizzahandler.zip pizzahandler

aws lambda update-function-code --function-name bhava_bot --zip-file fileb://pizzahandler.zip