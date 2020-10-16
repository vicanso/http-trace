# http trace

[![Build Status](https://img.shields.io/travis/vicanso/http-trace.svg?label=linux+build)](https://travis-ci.org/vicanso/http-trace)


HTTP Request trace, timing and request's information. 
Timing include `dns`, `connect`, `tls`, `first response byte` and so on.

events:
- GetConn
- DNSStart
- DNSDone
- ConnectStart
- ConnectDone
- TLSHandshakeStart
- TLSHandshakeDone
- GotConn
- WroteHeaders
- GotFirstResponseByte

```go
trace, ht := NewClientTrace()
ctx := context.Background()
ctx = httptrace.WithClientTrace(ctx, trace)
req, _ := http.NewRequest("GET", "https://www.baidu.com/", nil)

req = req.WithContext(ctx)
resp, _ := http.DefaultClient.Do(req)

ht.Finish()
stats := ht.Stats()
fmt.Println(stats)
fmt.Println(resp.Status)
```

