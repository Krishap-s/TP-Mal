package main

import (
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
)

const (
	SERVER_HOST = "localhost"
	SERVER_PORT = "7331"
	SERVER_TYPE = "tcp"
)

func main() {
	log.Printf("Parsing private key")
	pemData, err := os.ReadFile("keys/private.pem")
	if err != nil {
		log.Fatalf("Error reading key file: %v", err)
	}
	keyData, _ := pem.Decode(pemData)
	privKeyInterface, err := x509.ParsePKCS8PrivateKey(keyData.Bytes)
	if err != nil {
		log.Fatalf("Error parsing key data: %v", err)
	}
	privKey, ok := privKeyInterface.(*ecdsa.PrivateKey)
	if !ok {
		log.Fatalf("PKCS8 data is not a valid ECDH key")
	}
	if err != nil {
		log.Fatalf("Error converting to ecdh key: %v", err)
	}
	log.Print("Server Starting ...")
	server, err := net.Listen(SERVER_TYPE, SERVER_HOST+":"+SERVER_PORT)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	defer server.Close()
	log.Printf("TCP Server started on %s:%s", SERVER_HOST, SERVER_PORT)
	fmt.Println("Waiting for client...")
	for {
		connection, err := server.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		fmt.Println("client connected")
		go processClient(connection, privKey)
	}
}

func processClient(connection net.Conn, privKey *ecdsa.PrivateKey) {
	XBuff := make([]byte, 32)
	YBuff := make([]byte, 32)
	_, err := connection.Read(XBuff)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
		connection.Close()
		return
	}
	_, err = connection.Read(YBuff)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
		connection.Close()
		return
	}
	tpmX := big.NewInt(0).SetBytes(XBuff)
	tpmY := big.NewInt(0).SetBytes(YBuff)
	log.Printf("%v", elliptic.P256().IsOnCurve(tpmX, tpmY))
	size := (privKey.Params().N.BitLen() + 7) / 8
	outPointX, _ := elliptic.P256().ScalarMult(tpmX, tpmY, privKey.D.FillBytes(make([]byte, size)))
	log.Printf("X point is :%v", outPointX.Bytes())
	connection.Close()
}
