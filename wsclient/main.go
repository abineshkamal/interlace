// Command wsclient connects to a WebSocket through Interlace's proxy, sends a
// message and prints the echo. Used to verify WebSocket proxying/logging.
package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	target := "ws://127.0.0.1:9000/ws"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}
	proxyURL, _ := url.Parse("http://127.0.0.1:8080")
	dialer := websocket.Dialer{
		Proxy:            http.ProxyURL(proxyURL),
		HandshakeTimeout: 10 * time.Second,
	}
	c, _, err := dialer.Dial(target, nil)
	if err != nil {
		fmt.Println("dial error:", err)
		os.Exit(1)
	}
	defer c.Close()

	for _, msg := range []string{"hello interlace", "second message"} {
		if err := c.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
			fmt.Println("write error:", err)
			return
		}
		_, reply, err := c.ReadMessage()
		if err != nil {
			fmt.Println("read error:", err)
			return
		}
		fmt.Printf("sent %q -> got %q\n", msg, reply)
	}
}
