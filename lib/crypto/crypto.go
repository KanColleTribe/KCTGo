package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
)

type Crypto struct {
	mode  string
	nonce []byte
}

func (c Crypto) Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	var block cipher.Block
	var ciphertext []byte
	var err error

	switch c.mode {
	case "aes":
		block, err = aes.NewCipher(key)
		if err != nil {
			return ciphertext, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return ciphertext, err
		}

		ciphertext = gcm.Seal(nil, c.nonce, plaintext, nil)
	case "3des":
		block, err = des.NewTripleDESCipher(key)
		if err != nil {
			return ciphertext, err
		}
		ciphertext = make([]byte, len(plaintext))
		stream := cipher.NewCFBEncrypter(block, c.nonce)
		stream.XORKeyStream(ciphertext, plaintext)
	default:
	}

	return ciphertext, nil
}

func (c Crypto) Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	var block cipher.Block
	var plaintext []byte
	var err error

	switch c.mode {
	case "aes":
		block, err = aes.NewCipher(key)
		if err != nil {
			return plaintext, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return plaintext, err
		}

		plaintext, err = gcm.Open(nil, c.nonce, ciphertext, nil)
		return plaintext, err
	case "3des":
		block, err = des.NewTripleDESCipher(key)
		if err != nil {
			return plaintext, err
		}

		stream := cipher.NewCFBDecrypter(block, c.nonce)
		stream.XORKeyStream(ciphertext, ciphertext)
		return ciphertext, err
	default:
	}

	return plaintext, err
}
