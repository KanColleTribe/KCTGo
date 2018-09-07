package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
)

func TestAES(t *testing.T) {
	nonce, _ := hex.DecodeString("64a9433eae7ccceee2fc0eda")
	c := Crypto{
		mode:  "aes",
		nonce: nonce,
	}

	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	ciphertext, err := c.Encrypt([]byte("test plaintext"), key)
	plaintext, err := c.Decrypt(ciphertext, key)

	if err != nil {
		t.Fatal(err)
	} else {
		t.Logf("%x\n", ciphertext)
		t.Logf("%s\n", plaintext)
	}
}

func Test3DES(t *testing.T) {
	nonce, _ := hex.DecodeString("64a9433eae7cccee")
	c := Crypto{
		mode:  "3des",
		nonce: nonce,
	}

	key := make([]byte, 24)
	io.ReadFull(rand.Reader, key)

	ciphertext, err := c.Encrypt([]byte("test plaintext"), key)
	plaintext, err := c.Decrypt(ciphertext, key)

	if err != nil {
		t.Fatal(err)
	} else {
		t.Logf("%x\n", ciphertext)
		t.Logf("%s\n", plaintext)
	}
}
