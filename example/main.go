package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptrace"

	ht "github.com/vicanso/http-trace"
)

func main() {
	trace, ht := ht.NewClientTrace()
	ctx := context.Background()
	ctx = httptrace.WithClientTrace(ctx, trace)
	req, _ := http.NewRequest("GET", "https://www.baidu.com/", nil)

	req = req.WithContext(ctx)
	resp, _ := http.DefaultClient.Do(req)

	ht.Finish()
	stats := ht.Stats()
	fmt.Println(stats)
	fmt.Println(resp.Status)

}
