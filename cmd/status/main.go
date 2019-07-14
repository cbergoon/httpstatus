package main

import (
	"fmt"

	"github.com/cbergoon/httpstatus"
)

func main() {
	// Good Example Sites: badssl.com, neverssl.com
	t, err := httpstatus.NewHttpStatusTester("expired.badssl.com/")
	if err != nil {
		fmt.Println(err)
	}

	t.Insecure = false
	t.Run()
	fmt.Printf("%+v", t)
	for _, s := range t.Statistics {
		fmt.Printf("%+v", s)
	}
}
