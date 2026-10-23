// Captures the ClientHello uTLS would build for a Chrome or Firefox fingerprint: the reference our
// Hello is compared with (tests/hellostruct.py). Run with Go 1.24+, modules from Xray-core's go.mod
// (uTLS v1.8.x):
//
//	go run hello.go auto|133|131|120|firefox|148 out.bin
//
// uTLS "auto" is currently Chrome 133: the X25519MLKEM768 hybrid, ALPS with the new code 0x44cd,
// ECH GREASE. It is the fingerprint Xray-core uses with fp=chrome (transport/internet/tls).
// "firefox" is HelloFirefox_Auto, currently Firefox 148, what Xray-core uses with fp=firefox.
package main

import (
	"fmt"
	"net"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"
)

func main() {
	var id utls.ClientHelloID
	switch os.Args[1] {
	case "auto":
		id = utls.HelloChrome_Auto
	case "133":
		id = utls.HelloChrome_133
	case "131":
		id = utls.HelloChrome_131
	case "120":
		id = utls.HelloChrome_120
	case "firefox":
		id = utls.HelloFirefox_Auto
	case "148":
		id = utls.HelloFirefox_148
	default:
		panic(os.Args[1])
	}
	fmt.Println("uTLS:", id.Client, id.Version)
	c1, c2 := net.Pipe()
	go func() {
		buf := make([]byte, 65536)
		n, _ := c2.Read(buf)
		os.WriteFile(os.Args[2], buf[:n], 0644)
		c2.Close()
	}()
	u := utls.UClient(c1, &utls.Config{ServerName: "www.example.com", InsecureSkipVerify: true}, id)
	u.SetDeadline(time.Now().Add(2 * time.Second))
	_ = u.BuildHandshakeState()
	_ = u.Handshake()
}
