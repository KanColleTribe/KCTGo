package remote

import (
	"bufio"
	//	"bytes"
	"fmt"
	//	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
)

type remoteServer struct {
	ip   string
	port string
}

func NewRemoteServer(ip string, port string) remoteServer {
	server := remoteServer{
		ip:   ip,
		port: port,
	}

	return server
}

func proxyHandler(conn net.Conn) {
	defer conn.Close()
	fmt.Println("-----New connection from " + conn.RemoteAddr().String())
	conn_reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(conn_reader)
	if err != nil {
		log.Fatal(err)
	}

	req.URL, err = url.Parse(req.RequestURI)
	if err != nil {
		log.Fatal(err)
	}
	req.RequestURI = ""

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	resp_bytes, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Fatal(err)
	}

	conn_writer := bufio.NewWriter(conn)
	conn_writer.Write(resp_bytes)
	conn_writer.Flush()
}

func (server remoteServer) Run() {
	ln, err := net.Listen("tcp", server.ip+":"+server.port)
	fmt.Println(ln)
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		//		defer conn.Close()

		go proxyHandler(conn)
	}
}

func main() {
	//	server := NewRemoteServer("127.0.0.1", "18999")
	//	server.Run()
}
