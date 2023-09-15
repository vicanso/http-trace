# http trace

[![Build Status](https://github.com/vicanso/http-trace/workflows/Test/badge.svg)](https://github.com/vicanso/http-trace/actions)


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
- WroteRequest
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

