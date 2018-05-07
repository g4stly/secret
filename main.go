package main

import (
	"fmt"
	"flag"
	"crypto/aes"
	"crypto/sha256"
	"io/ioutil"
	"os"
)

var passwd	= flag.String("key", "", "key: the key used to encrypt/decrypt the message")
var decrypt	= flag.Bool("d", false, "decrypt: decrypt stdin with given key")
var raw		= flag.Bool("r", false, "raw: do not add whitespace to the end of the output")

func encryptMessage(msg, key []byte) ([]byte, error) {
	salty_key := sha256.Sum256(key)
	cipher, err := aes.NewCipher(salty_key[:])
	if err != nil { return nil, err }

	blockSize := cipher.BlockSize()
	difference := len(msg) % blockSize

	if difference != 0 {
		adjustment := blockSize - difference
		//fmt.Printf("padding from %v to %v with %v zeroes.\n",
			//len(msg), len(msg) + adjustment, adjustment)
		for i := 0; i < adjustment ; i++ {
			msg = append(msg, 1)
		}
		//fmt.Printf("msg is now %v bytes long.\n", len(msg))
	}

	var result []byte
	for i := 0; i < len(msg) / blockSize; i++ {
		local_res := make([]byte, blockSize)
		local_msg := msg[i*blockSize:]
		cipher.Encrypt(local_res, local_msg)

		result = append(result, local_res...)
	}

	return result, nil
}

func decryptMessage(msg, key []byte) ([]byte, error) {
	salty_key := sha256.Sum256(key)
	cipher, err := aes.NewCipher(salty_key[:])
	if err != nil { return nil, err }

	blockSize := cipher.BlockSize()
	difference := len(msg) % blockSize

	if difference != 0 {
		adjustment := blockSize - difference
		//fmt.Printf("padding from %v to %v with %v zeroes.\n",
			//len(msg), len(msg) + adjustment, adjustment)
		for i := 0; i < adjustment ; i++ {
			msg = append(msg, 1)
		}
		//fmt.Printf("msg is now %v bytes long.\n", len(msg))
	}

	var result []byte
	for i := 0; i < len(msg) / blockSize; i++ {
		local_res := make([]byte, blockSize)
		local_msg := msg[i*blockSize:]
		cipher.Decrypt(local_res, local_msg)

		result = append(result, local_res...)
	}

	return result, nil
}

func main() {
	flag.Parse()

	if *passwd == "" {
		fmt.Printf("You must supply a key with the `-key` option.\n")
		return
	}

	msg, err := ioutil.ReadAll(os.Stdin)
	if err != nil { panic(err) }

	if *decrypt {
		plaintext, err := decryptMessage(msg[:len(msg)-1], []byte(*passwd))
		if err != nil { panic(err) }
		if !*raw { plaintext = append(plaintext, '\n') }
		os.Stdout.Write(plaintext)
		return
	}

	ciphertext, err := encryptMessage(msg[:len(msg)-1], []byte(*passwd))
	if err != nil { panic(err) }
	if !*raw { ciphertext = append(ciphertext, '\n') }
	os.Stdout.Write(ciphertext)
}
