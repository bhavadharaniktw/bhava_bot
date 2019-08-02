package main

import (
	"testing"

	"github.com/tj/assert"
)

func Test_dialogflowRequestHandler(t *testing.T) {
	res, err := getResponseFromDialogflow("pizza")
	if err != nil {
		t.Errorf("Encountered error: %s", err)
	}
	assert.EqualValues(t, "Your order have been placed..!", res)

}
