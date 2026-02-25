package main

import (
	"fmt"
	"net/http"
)

func main() {
	res, err := http.Get("https://espinabrian.com/")
	if err != nil {

		fmt.Print("Site Down")
		return
	}
	fmt.Print(res.StatusCode)
}
