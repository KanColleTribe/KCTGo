package local

import (
	"../lib/log"
	"bufio"
	//	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
)

type localServer struct {
	ip           string
	port         string
	protocol     string
	remoteServer string
	remotePort   string
	logger       *log.Logger
}

func NewLocalServer(ip string, port string, protocol string,
	rtServer string, rtPort string, logger *log.Logger) localServer {
	server := localServer{
		ip:           ip,
		port:         port,
		protocol:     protocol,
		remoteServer: rtServer,
		remotePort:   rtPort,
		logger:       logger,
	}

	return server
}

func (server localServer) Handler(w http.ResponseWriter, req *http.Request) {
	conn, err := net.Dial(
		server.protocol,
		server.remoteServer+":"+server.remotePort,
	)
	if err != nil {
		err_msg := "Cannot connect to remote server -- " + err.Error()
		server.logger.Error(err_msg)
		return
	}
	defer conn.Close()

	req_bytes, err := httputil.DumpRequest(req, true)
	if err != nil {
		err_msg := "Request dump failed -- " + err.Error()
		server.logger.Error(err_msg)
		return
	}

	conn_writer := bufio.NewWriter(conn)
	conn_writer.Write(req_bytes)
	conn_writer.Flush()

	conn_reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(conn_reader, req)
	if err != nil {
		err_msg := "Cannot get response from remote server -- " + err.Error()
		server.logger.Error(err_msg)
		return
	}

	for k, v := range resp.Header {
		w.Header().Set(k, strings.Join(v, ","))
	}

	resp_body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err_msg := "Cannot get response content -- " + err.Error()
		server.logger.Error(err_msg)
		return
	}
	defer resp.Body.Close()
	w.Write(resp_body)
}

func (server localServer) Run() {
	server.logger.Info("Local proxy server running...Server ip: " + server.ip + ":" + server.port)
	http.HandleFunc("/", server.Handler)

	err := http.ListenAndServe(server.ip+":"+server.port, nil)
	if err != nil {
		err_msg := "Server initialization failed. -- " + err.Error()
		server.logger.Error(err_msg)
		server.logger.Fatal(err_msg)
		return
	}
}

//func main() {
//	server := NewLocalServer("127.0.0.1", "18996", "tcp",
//		"127.0.0.1", "18999")
//	server.Run()
//}
