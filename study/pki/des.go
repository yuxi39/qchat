package pki

import "crypto/des"

func Enc(key, plaintext []byte) []byte {
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, block.BlockSize())
	block.Encrypt(ciphertext, plaintext)

	return ciphertext
}

func Dec(key, ciphertext []byte) []byte {
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}
	plaintext := make([]byte, block.BlockSize())
	block.Decrypt(plaintext, ciphertext)

	return plaintext
}