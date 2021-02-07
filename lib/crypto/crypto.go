package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
)

type Crypto struct {
	Mode  string
	Nonce []byte
	Label []byte
}

var pssOption = rsa.PSSOptions{
	SaltLength: rsa.PSSSaltLengthAuto,
	Hash:       crypto.SHA256,
}

func (c Crypto) Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	var block cipher.Block
	var ciphertext []byte
	var err error

	switch c.Mode {
	case "aes":
		block, err = aes.NewCipher(key)
		if err != nil {
			return ciphertext, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return ciphertext, err
		}

		ciphertext = gcm.Seal(nil, c.Nonce, plaintext, nil)
	case "3des":
		block, err = des.NewTripleDESCipher(key)
		if err != nil {
			return ciphertext, err
		}
		ciphertext = make([]byte, len(plaintext))
		stream := cipher.NewCFBEncrypter(block, c.Nonce)
		stream.XORKeyStream(ciphertext, plaintext)
	default:
	}

	return ciphertext, nil
}

func (c Crypto) Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	var block cipher.Block
	var plaintext []byte
	var err error

	switch c.Mode {
	case "aes":
		block, err = aes.NewCipher(key)
		if err != nil {
			return plaintext, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return plaintext, err
		}

		plaintext, err = gcm.Open(nil, c.Nonce, ciphertext, nil)
		return plaintext, err
	case "3des":
		block, err = des.NewTripleDESCipher(key)
		if err != nil {
			return plaintext, err
		}

		stream := cipher.NewCFBDecrypter(block, c.Nonce)
		stream.XORKeyStream(ciphertext, ciphertext)
		return ciphertext, err
	default:
	}

	return plaintext, err
}

// RSA

func (c Crypto) RSAEncrypt(plaintext []byte, pk *rsa.PublicKey, random io.Reader) ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), random, pk, plaintext, c.Label)

	return ciphertext, err
}

func (c Crypto) RSADecrypt(ciphertext []byte, sk *rsa.PrivateKey, random io.Reader) ([]byte, error) {
	plaintext, err := rsa.DecryptOAEP(sha256.New(), random, sk, ciphertext, c.Label)

	return plaintext, err
}

// For HMAC

func GetHMAC(content []byte, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(content)
	return h.Sum(nil)
}

func CheckHMAC(content1 []byte, content2 []byte) bool {
	return hmac.Equal(content1, content2)
}

// Signature

func Sign(content []byte, sk *rsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(content)
	signature, err := rsa.SignPSS(rand.Reader, sk, crypto.SHA256, hashed[:], &pssOption)

	return signature, err
}

func VerifySignature(content []byte, signature []byte, pk *rsa.PublicKey) error {
	hashed := sha256.Sum256(content)
	return rsa.VerifyPSS(pk, crypto.SHA256, hashed[:], signature, &pssOption)
}

// Load && Save key files

func LoadSK(filename string, passphrase []byte) (rsa.PrivateKey, error) {
	var sk = &rsa.PrivateKey{}
	var err error

	key, err := ioutil.ReadFile(filename)
	if err != nil {
		return *sk, err
	}

	block, _ := pem.Decode(key)
	if block == nil {
		return *sk, errors.New("Empty block. Please check your key file!")
	}
	if len(passphrase) > 0 {
		decrypted, err := x509.DecryptPEMBlock(block, passphrase)
		if err != nil {
			return *sk, err
		}
		sk, err = x509.ParsePKCS1PrivateKey(decrypted)
	} else {
		sk, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	if err != nil {
		return rsa.PrivateKey{}, err
	} else {
		return *sk, err
	}
}

func LoadPK(filename string) (interface{}, error) {
	var err error

	key, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(key)
	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	} else {
		return pk, err
	}
}
