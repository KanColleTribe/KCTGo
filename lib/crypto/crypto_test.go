package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"io"
	"testing"
)

func TestAES(t *testing.T) {
	nonce, _ := hex.DecodeString("64a9433eae7ccceee2fc0eda")
	c := Crypto{
		Mode:  "aes",
		Nonce: nonce,
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
		Mode:  "3des",
		Nonce: nonce,
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

func TestRSA(t *testing.T) {
	c := Crypto{
		Label: []byte("test label"),
	}

	random := make([]byte, 1024)
	io.ReadFull(rand.Reader, random)

	sk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.PublicKey

	ciphertext, err := c.RSAEncrypt([]byte("test plaintext"), &pk, bytes.NewReader(random))
	if err != nil {
		t.Fatal(err)
	} else {
		t.Logf("%x\n", ciphertext)
	}

	plaintext, err := c.RSADecrypt(ciphertext, sk, bytes.NewReader(random))
	if err != nil {
		t.Fatal(err)
	} else {
		t.Logf("%s\n", plaintext)
	}
}

func TestHMAC(t *testing.T) {
	msg := []byte("test message")

	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	hmac := GetHMAC(msg, key)
	t.Logf("%x\n", hmac)

	equal := CheckHMAC(hmac, hmac)
	t.Logf("%t\n", equal)
}

func TestSignature(t *testing.T) {
	sk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.PublicKey

	message := []byte("Test message.")

	signature, err := Sign(message, sk)
	if err != nil {
		t.Fatal(err)
	} else {
		t.Logf("%x\n", signature)
	}

	check := VerifySignature(message, signature, &pk)
	if check != nil {
		t.Fatal(check)
	} else {
		t.Log("true")
	}

}

// Test key pair: sk.key and pk.key
// Passphrase: testkey

func TestKeyFile(t *testing.T) {
	sk, err := LoadSK("sk.key", []byte("testkey"))
	if err != nil {
		t.Fatal(err)
	} else {
		t.Logf("%x\n", sk)
	}

	sk2, err := LoadSK("noencryption_sk.key", nil)
	if err != nil {
		t.Fatal(err)
	} else {
		t.Logf("%x\n", sk2)
	}

	pk, err := LoadPK("pk.key")
	if err != nil {
		t.Fatal(err)
	} else {
		t.Logf("%x\n", pk)
	}

	if key, ok := pk.(*rsa.PublicKey); ok {
		t.Logf("%x\n", key)

		c := Crypto{
			Label: []byte("test label"),
		}

		random := make([]byte, 1024)
		io.ReadFull(rand.Reader, random)

		ciphertext, err := c.RSAEncrypt([]byte("test plaintext"), key, bytes.NewReader(random))
		if err != nil {
			t.Fatal(err)
		} else {
			t.Logf("%x\n", ciphertext)
		}

		plaintext, err := c.RSADecrypt(ciphertext, &sk, bytes.NewReader(random))
		if err != nil {
			t.Fatal(err)
		} else {
			t.Logf("%s\n", plaintext)
		}
	}
}
