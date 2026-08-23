package pki

import (
	"bytes"
	"fmt"
	"io"
	"net"
)

var key = "12345678"
var addr = "localhost:9981"

// blockSize is the DES block size in bytes.
const blockSize = 8

func Client() {
	raddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		panic(err)
	}
	conn, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	if _, err := conn.Write(DataProtect([]byte("Hello World!"))); err != nil {
		panic(err)
	}
}

func Serve(url string) {
	laddr, err := net.ResolveTCPAddr("tcp", url)
	if err != nil {
		panic(err)
	}
	ln, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go Handle(conn)
	}
}

func Handle(conn net.Conn) {
	defer conn.Close()

	content, err := io.ReadAll(conn)
	if err != nil {
		fmt.Println("read error:", err)
		return
	}
	fmt.Printf("%s\n", DataRestore(content))
}

func DataProtect(data []byte) []byte {
	padded := Pad(data, blockSize)
	pieces := Split(padded)
	for i := range pieces {
		pieces[i] = Enc([]byte(key), pieces[i])
	}
	return Merge(pieces)
}

func DataRestore(data []byte) []byte {
	pieces := Split(data)
	for i := range pieces {
		pieces[i] = Dec([]byte(key), pieces[i])
	}
	return Unpad(Merge(pieces))
}

// Split divides data into blockSize-byte chunks (the final chunk may be short).
func Split(data []byte) [][]byte {
	var ans [][]byte
	for i := 0; i < len(data); i += blockSize {
		end := i + blockSize
		if end > len(data) {
			end = len(data)
		}
		ans = append(ans, data[i:end])
	}
	return ans
}

// Merge concatenates all chunks into a single slice.
func Merge(data [][]byte) []byte {
	var ans []byte
	for i := range data {
		ans = append(ans, data[i]...)
	}
	return ans
}

// Pad appends PKCS#7 padding so the length becomes a multiple of blockSize.
func Pad(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(n)}, n)...)
}

// Unpad removes the PKCS#7 padding appended by Pad.
func Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	n := int(data[len(data)-1])
	if n <= 0 || n > blockSize || n > len(data) {
		return data
	}
	return data[:len(data)-n]
}
