package local

import (
	"bufio"
	//	"fmt"
	"bytes"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/wuyuMk7/KCTGo/lib/crypto"
	"github.com/wuyuMk7/KCTGo/lib/log"
)

type localServer struct {
	ip           string
	port         string
	protocol     string
	remoteServer string
	remotePort   string
	logger       *log.Logger
	username     string
	password     string
	crypto       crypto.Crypto
	pk           string
}

func NewLocalServer(ip string, port string, protocol string,
	rtServer string, rtPort string, logger *log.Logger,
	username string, password string, label string,
	cryptomode string, pk string) localServer {

	if len(cryptomode) <= 0 {
		cryptomode = "aes"
	}

	server := localServer{
		ip:           ip,
		port:         port,
		protocol:     protocol,
		remoteServer: rtServer,
		remotePort:   rtPort,
		logger:       logger,
		username:     username,
		password:     password,
		crypto:       crypto.Crypto{Mode: cryptomode, Nonce: []byte(""), Label: []byte(label)},
		pk:           pk,
	}

	return server
}

func (server localServer) Handler(w http.ResponseWriter, req *http.Request) {
	conn, err := net.DialTimeout(
		server.protocol,
		server.remoteServer+":"+server.remotePort,
		10000000,
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

	key := []byte("a32fs5623984wer4")
	server.crypto.Nonce = []byte("5a3de1763215")

	encrypted_bytes, err := server.crypto.Encrypt(req_bytes, key)
	content_length := []byte(strconv.FormatInt(int64(len(encrypted_bytes)), 16))
	content_length_bytes := make([]byte, 16)
	copy(content_length_bytes[16-len(content_length):], content_length)

	conn_writer := bufio.NewWriter(conn)
	conn_writer.Write(content_length_bytes)
	conn_writer.Write(encrypted_bytes)
	conn_writer.Flush()

	conn.SetReadDeadline(time.Now().Add(1000 * time.Second))
	conn_content_reader := bufio.NewReader(conn)

	conn_content_length_bytes := make([]byte, 16)
	_, err = conn_content_reader.Read(conn_content_length_bytes)
	if err != nil {
		err_msg := "Cannot read data length from server response -- " + err.Error()
		server.logger.Error(err_msg)
		return
	}

	conn_content_length, err := strconv.ParseInt(string(bytes.Trim(conn_content_length_bytes, "\x00")), 16, 0)
	if err != nil {
		err_msg := "Cannot convert data length from server response -- " + err.Error()
		server.logger.Error(err_msg)
		return
	}

	conn_content := make([]byte, 0, conn_content_length)
	buf_tmp := make([]byte, conn_content_reader.Size())
	for int64(len(conn_content)) < conn_content_length {
		count, err := conn_content_reader.Read(buf_tmp)
		if err != nil {
			err_msg := "Cannot read data length from server response -- " + err.Error()
			server.logger.Error(err_msg)
			return
		}

		conn_content = append(conn_content, buf_tmp[:count]...)
	}

	conn_content = bytes.Trim(conn_content, " \r\n")
	decrypted_bytes, err := server.crypto.Decrypt(conn_content, key)
	if err != nil {
		err_msg := "Cannot decrypt data from server response -- " + err.Error()
		server.logger.Error(err_msg)
		return
	}

	conn_reader := bufio.NewReader(bytes.NewReader(decrypted_bytes))
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
