package remote

import (
	"../lib/log"
	"bufio"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
)

type remoteServer struct {
	ip       string
	port     string
	protocol string
	crypto   string
	logger   *log.Logger
}

func NewRemoteServer(ip string, port string, protocol string, crypto string, logger *log.Logger) remoteServer {
	server := remoteServer{
		ip:       ip,
		port:     port,
		protocol: protocol,
		crypto:   crypto,
		logger:   logger,
	}

	return server
}

func proxyHandler(conn net.Conn, logger *log.Logger) {
	defer conn.Close()

	conn_reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(conn_reader)
	if err != nil {
		err_msg := "Cannot extract request from user request -- " + err.Error()
		logger.Error(err_msg)
		return
	}

	req.URL, err = url.Parse(req.RequestURI)

	if err != nil {
		err_msg := "Cannot parse URI from user request -- " + err.Error()
		logger.Error(err_msg)
		return
	}
	req.RequestURI = ""

	logger.Info("*** New connection from " + conn.RemoteAddr().String() + " to " + req.URL.String() + " **")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		err_msg := "Cannot connect to the destination -- " + err.Error()
		logger.Error(err_msg)
		return
	}

	resp_bytes, err := httputil.DumpResponse(resp, true)
	if err != nil {
		err_msg := "Cannot convert response to bytes -- " + err.Error()
		logger.Error(err_msg)
		return
	}

	conn_writer := bufio.NewWriter(conn)
	conn_writer.Write(resp_bytes)
	conn_writer.Flush()
}

func (server remoteServer) Run() {
	ln, err := net.Listen(server.protocol, server.ip+":"+server.port)

	if err != nil {
		err_msg := "Server initialization failed. -- " + err.Error()
		server.logger.Error(err_msg)
		server.logger.Fatal(err_msg)
	}

	server.logger.Info("Server running... Protocol: " + server.protocol + ", ip: " + server.ip + ":" + server.port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			err_msg := "Cannot accept connection from user -- " + err.Error()
			server.logger.Error(err_msg)
			return
		}

		go proxyHandler(conn, server.logger)
	}
}

func main() {
	//	server := NewRemoteServer("127.0.0.1", "18999")
	//	server.Run()
}
