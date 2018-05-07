package main

import (
	"crypto/aes"
	"crypto/sha256"
	"flag"
	"io/ioutil"
	"log"
	"os"
)

var key = flag.String("k", "", "key: the key used to encrypt/decrypt the message")
var encrypt = flag.Bool("e", false, "encrypt: ecrypt mode (default)")
var decrypt = flag.Bool("d", false, "decrypt: decrypt mode")
var verbose = flag.Bool("v", false, "verbose: print extraneous debug info (to stderr)")
var raw = flag.Bool("r", false, "raw: do not append a newline to the output")

var out = log.New(os.Stderr, "", log.Ltime|log.Lshortfile)

func main() {
	// parse flags, ensure we have a key
	flag.Parse()
	if *key == "" {
		out.Fatalf("The `-k` option is mandatory. See `-h` for help.\n")
	}

	// read from stdin (trim mysterious character at the end)
	msg, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		out.Fatalf("ReadAll(): %v\n", err)
	}
	msg = msg[:len(msg)-1]

	// salt key & create cipher
	salty_key := sha256.Sum256([]byte(*key))
	cipher, err := aes.NewCipher(salty_key[:])
	if err != nil {
		out.Fatalf("NewCipher(): %v\n", err)
	}

	blockSize := cipher.BlockSize()
	difference := len(msg) % blockSize

	// we want the length of our message congruent modulo the block size of our cipher
	if difference != 0 {
		adjustment := blockSize - difference
		for i := 0; i < adjustment; i++ {
			msg = append(msg, 0)
		}
	}

	// get 'er done
	var result []byte
	for i := 0; i < len(msg)/blockSize; i++ {
		local_res := make([]byte, blockSize)
		local_msg := msg[i*blockSize:]

		if *decrypt {
			if *encrypt {
				out.Printf("What are you doing?")
			}
			cipher.Decrypt(local_res, local_msg)
		} else {
			cipher.Encrypt(local_res, local_msg)
		}

		result = append(result, local_res...)
	}

	// output
	if !*raw {
		result = append(result, '\n')
	}
	os.Stdout.Write(result)
}
