package local

import (
	"fmt"
	//	"io"
	"bufio"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	//"net/url"
	"io/ioutil"
	"strings"
)

type localServer struct {
	ip           string
	port         string
	protocol     string
	remoteServer string
	remotePort   string
}

func NewLocalServer(ip string, port string, protocol string,
	rtServer string, rtPort string) localServer {
	server := localServer{
		ip:           ip,
		port:         port,
		protocol:     protocol,
		remoteServer: rtServer,
		remotePort:   rtPort,
	}

	return server
}

func (server localServer) Handler(w http.ResponseWriter, req *http.Request) {
	conn, err := net.Dial(
		server.protocol,
		server.remoteServer+":"+server.remotePort,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	req_bytes, err := httputil.DumpRequest(req, true)
	if err != nil {
		log.Fatal(err)
	}

	conn_writer := bufio.NewWriter(conn)
	conn_writer.Write(req_bytes)
	conn_writer.Flush()

	conn_reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(conn_reader, req)
	if err != nil {
		log.Fatal(err)
	}

	for k, v := range resp.Header {
		w.Header().Set(k, strings.Join(v, ","))
	}

	resp_body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	w.Write(resp_body)
}

func (server localServer) Run() {
	fmt.Println(server.ip + ":" + server.port)
	http.HandleFunc("/", server.Handler)
	log.Fatal(http.ListenAndServe(server.ip+":"+server.port, nil))
}

//func main() {
//	server := NewLocalServer("127.0.0.1", "18996", "tcp",
//		"127.0.0.1", "18999")
//	server.Run()
//}
