<h1 align="center">HTTP Status</h1>
<p align="center">
<a href="https://goreportcard.com/report/github.com/cbergoon/httpstatus"><img src="https://goreportcard.com/badge/github.com/cbergoon/httpstatus?1=1" alt="Report"></a>
<a href="https://godoc.org/github.com/cbergoon/httpstatus"><img src="https://img.shields.io/badge/godoc-reference-brightgreen.svg" alt="Docs"></a>
<a href="#"><img src="https://img.shields.io/badge/version-0.1.0-brightgreen.svg" alt="Version"></a>
</p>

HTTP Status collects timing and other statistics about an HTTP request. 

This is an adaptation of davecheney/httpstat making it usable by other applications as a library. 

#### Documentation 

See the docs [here](https://godoc.org/github.com/cbergoon/httpstatus).

#### Install
```
go get github.com/cbergoon/httpstatus
```

#### Example Usage

```go
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
```

#### License
This project is licensed under the MIT License.
