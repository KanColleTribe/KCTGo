package remote

import (
	"bufio"
	"bytes"
	"github.com/wuyuMk7/KCTGo/lib/log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/wuyuMk7/KCTGo/lib/crypto"
)

type remoteServer struct {
	ip       string
	port     string
	protocol string
	logger   *log.Logger
	sk       string
}

func NewRemoteServer(ip string, port string, protocol string,
	logger *log.Logger, sk string) remoteServer {

	server := remoteServer{
		ip:       ip,
		port:     port,
		protocol: protocol,
		logger:   logger,
		sk:       sk,
	}

	return server
}

func proxyHandler(conn net.Conn, logger *log.Logger) {
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	conn_content_reader := bufio.NewReader(conn)

	conn_content_length_bytes := make([]byte, 16)
	_, err := conn_content_reader.Read(conn_content_length_bytes)
	if err != nil {
		err_msg := "Cannot read data length from user request -- " + err.Error()
		logger.Error(err_msg)
		return
	}

	conn_content_length, err := strconv.ParseInt(string(bytes.Trim(conn_content_length_bytes, "\x00")), 16, 0)
	if err != nil {
		err_msg := "Cannot convert data length from user request -- " + err.Error()
		logger.Error(err_msg)
		return
	}

	conn_content := make([]byte, 0, conn_content_length)
	buf_tmp := make([]byte, conn_content_reader.Size())
	for int64(len(conn_content)) < conn_content_length {
		count, err := conn_content_reader.Read(buf_tmp)
		if err != nil {
			err_msg := "Cannot read data length from server response -- " + err.Error()
			logger.Error(err_msg)
			return
		}

		conn_content = append(conn_content, buf_tmp[:count]...)
	}

	conn_content = bytes.Trim(conn_content, " \r\n")
	c := crypto.Crypto{
		Mode:  "aes",
		Nonce: []byte("5a3de1763215"),
		Label: []byte("sharing"),
	}
	key := []byte("a32fs5623984wer4")

	decrypted_bytes, err := c.Decrypt(conn_content, key)
	if err != nil {
		err_msg := "Cannot decrypt data from user request -- " + err.Error()
		logger.Error(err_msg)
		return
	}

	conn_reader := bufio.NewReader(bytes.NewReader(decrypted_bytes))
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

	encrypted_bytes, err := c.Encrypt(resp_bytes, key)
	if err != nil {
		err_msg := "Cannot encrypt response -- " + err.Error()
		logger.Error(err_msg)
		return
	}

	content_length := []byte(strconv.FormatInt(int64(len(encrypted_bytes)), 16))
	content_length_bytes := make([]byte, 16)
	copy(content_length_bytes[16-len(content_length):], content_length)

	conn_writer := bufio.NewWriter(conn)
	conn_writer.Write(content_length_bytes)
	conn_writer.Write(encrypted_bytes)
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
