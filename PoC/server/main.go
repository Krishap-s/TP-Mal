package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"

	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/legacy/tpm2"
)

const (
	SERVER_HOST = "192.168.122.1"
	SERVER_PORT = "445"
	SERVER_TYPE = "tcp"
)

var (
	TPM_CERT_POOL  = *x509.NewCertPool()
	payloadBytes   bytes.Buffer
	encPaylodBytes bytes.Buffer
	payloads       = make(map[string]*bytes.Buffer, 2)
)

func encryptedJsonSend(conn *textproto.Writer, tempCipher cipher.AEAD, data any) error {
	json, err := json.Marshal(data)
	if err != nil {
		return err
	}
	nonce := make([]byte, tempCipher.NonceSize())
	rand.Read(nonce)
	jsonEnc := tempCipher.Seal(nonce, nonce, json, nil)
	dotWriter := conn.DotWriter()
	if _, err = dotWriter.Write(jsonEnc); err != nil {
		return err
	}
	dotWriter.Close()
	return nil
}

func encryptedJsonRead(conn *textproto.Reader, tempCipher cipher.AEAD, data any) error {

	var readBuff bytes.Buffer
	if _, err := readBuff.ReadFrom(conn.DotReader()); err != nil {
		return err
	}

	encryptedJson := bytes.TrimSpace(readBuff.Bytes())
	readBuff.Reset()
	nonce, cipherText := encryptedJson[:tempCipher.NonceSize()], encryptedJson[tempCipher.NonceSize():]
	jsonData, err := tempCipher.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return err
	}
	return nil
}

func main() {
	pwd, _ := os.Getwd()
	log.Printf("Loading TPM root certificates")
	certsPath := filepath.Join(pwd, "certs")
	certificateFileNames, err := os.ReadDir(certsPath)
	if err != nil {
		log.Panicln(err)
	}
	for _, i := range certificateFileNames {
		derData, err := os.ReadFile(filepath.Join(certsPath, i.Name()))
		if err != nil {
			log.Panicln(err)
		}
		cert, err := x509.ParseCertificate(derData)
		if err != nil {
			log.Panic(err)
		}
		TPM_CERT_POOL.AddCert(cert)
	}
	log.Printf("Loading Payloads")
	payloadsPath := filepath.Join(pwd, "payloads")
	payloadFileNames, err := os.ReadDir(payloadsPath)
	if err != nil {
		log.Panicln(err)
	}
	for _, i := range payloadFileNames {
		payloadData, err := os.ReadFile(filepath.Join(payloadsPath, i.Name()))
		if err != nil {
			log.Panicln(err)
		}
		baseName, _ := strings.CutSuffix(i.Name(), filepath.Ext(i.Name()))
		payloads[baseName] = bytes.NewBuffer(payloadData)
	}
	log.Printf("Parsing private key")
	pemData, err := os.ReadFile(filepath.Join(pwd, "keys/private.pem"))
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
	log.Println("Waiting for client...")
	for {
		connection, err := server.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		log.Println("client connected")
		go processClient(connection, privKey)
	}
}

func processClient(connection net.Conn, privKey *ecdsa.PrivateKey) {
	defer connection.Close()
	log.Println("Phase 1")
	// Read challenge data
	connReader := textproto.NewReader(bufio.NewReader(connection))
	connWriter := textproto.NewWriter(bufio.NewWriter(connection))
	var readBuff bytes.Buffer
	var dotWriter io.WriteCloser
	_, err := readBuff.ReadFrom(connReader.DotReader())
	if err != nil {
		log.Panicln(err)
		return
	}
	challengeJson := readBuff.Bytes()
	readBuff.Reset()
	log.Println(readBuff.String())
	challengeData := struct {
		X string `json:"x"`
		Y string `json:"y"`
		C string `json:"c"`
	}{}
	err = json.Unmarshal(challengeJson, &challengeData)
	if err != nil {
		log.Println(err)
		return
	}
	x, err := base64.RawURLEncoding.DecodeString(challengeData.X)
	if err != nil {
		log.Println(err)
		return
	}
	y, err := base64.RawURLEncoding.DecodeString(challengeData.Y)
	if err != nil {
		log.Println(err)
		return
	}
	challenge, err := base64.RawURLEncoding.DecodeString(challengeData.C)
	if err != nil {
		log.Println(err)
		return
	}
	tpmX := big.NewInt(0).SetBytes(x)
	tpmY := big.NewInt(0).SetBytes(y)
	log.Printf("%v", elliptic.P256().IsOnCurve(tpmX, tpmY))
	size := (privKey.Params().N.BitLen() + 7) / 8
	outPointX, _ := elliptic.P256().ScalarMult(tpmX, tpmY, privKey.D.FillBytes(make([]byte, size)))
	log.Printf("X point is :%v", outPointX.Bytes())
	tempCipherBlock, err := aes.NewCipher(outPointX.Bytes())
	if err != nil {
		log.Println(err)
		return
	}
	tempCipher, err := cipher.NewGCM(tempCipherBlock)
	if err != nil {
		log.Println(err)
		return
	}
	nonce, cipherText := challenge[:tempCipher.NonceSize()], challenge[tempCipher.NonceSize():]
	challengeRsp, err := tempCipher.Open(nil, nonce, cipherText, nil)
	if err != nil {
		log.Println(err)
		return
	}
	dotWriter = connWriter.DotWriter()
	if _, err = dotWriter.Write(challengeRsp); err != nil {
		log.Println(err)
		return
	}
	dotWriter.Close()
	log.Println("Phase 2")
	attestData := struct {
		AttestParams *attest.AttestationParameters `json:"attest_params"`
		EkCert       []byte                        `json:"ek_cert"`
		EkUrl        string                        `json:"ek_url"`
		OS           string                        `json:"os"`
	}{}
	if err := encryptedJsonRead(connReader, tempCipher, &attestData); err != nil {
		log.Println(err)
		return
	}
	// Validate params sent
	var ekData bytes.Buffer
	if attestData.EkCert != nil {
		ekData.Read(attestData.EkCert)
	} else if attestData.EkUrl != "" {
		response, err := http.Get(attestData.EkUrl)
		if err != nil {
			log.Println(err)
			return
		}
		if response.StatusCode == 200 {
			ekData.ReadFrom(response.Body)
		} else {
			log.Println(errors.New("certificate not found"))
		}
	} else {
		log.Println(errors.New("no certificate found"))
		return
	}
	ekCert, err := attest.ParseEKCertificate(ekData.Bytes())
	if err != nil {
		log.Println(err)
		return
	}
	ekCert.UnhandledCriticalExtensions = nil

	params := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion20,
		EK:         ekCert.PublicKey,
		AK:         *attestData.AttestParams,
	}
	secretData, encCreds, err := params.Generate()
	if err != nil {
		log.Println(err)
		return
	}

	if err = encryptedJsonSend(connWriter, tempCipher, encCreds); err != nil {
		log.Println(err)
		return
	}
	decryptedSecretJson := struct {
		Secret []byte `json:"secret_data"`
	}{}
	if err = encryptedJsonRead(connReader, tempCipher, &decryptedSecretJson); err != nil {
		log.Println(err)
		return
	}

	if bytes.Equal(secretData, decryptedSecretJson.Secret) {
		log.Println("Valid Secret: Valid TPM")
	} else {
		log.Println("Invalid Secret")
	}
	log.Println("Phase 3")
	ak, err := attest.ParseAKPublic(attest.TPMVersion20, params.AK.Public)
	if err != nil {
		log.Println(err)
		return
	}
	bindingKeyCertification := attest.CertificationParameters{}
	if err = encryptedJsonRead(connReader, tempCipher, &bindingKeyCertification); err != nil {
		log.Println(err)
		return
	}
	if err = bindingKeyCertification.Verify(attest.VerifyOpts{
		Public: ak.Public,
		Hash:   ak.Hash,
	}); err != nil {
		log.Println(err)
		return
	}
	log.Println("Binding key verified")
	log.Println("Phase 4")
	// Encrypt payload with binding key
	tpmPub, err := tpm2.DecodePublic(bindingKeyCertification.Public)
	if err != nil {
		log.Println(err)
		return
	}
	cryptoPubKey, err := tpmPub.Key()
	if err != nil {
		log.Println(err)
		return
	}
	rsaPubKey := cryptoPubKey.(*rsa.PublicKey)

	log.Println(attestData.OS)
	payloadBuffer, ok := payloads[attestData.OS]
	if !ok {
		log.Panicln("Payload for os not found")
		return
	}
	payloadBytes.WriteString(base64.StdEncoding.EncodeToString(payloadBuffer.Bytes()))
	log.Println(payloadBytes.Len())
	for payloadBytes.Len() > 0 {
		encPayloadBlock, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, payloadBytes.Next(150), nil)
		if err != nil {
			log.Println(err)
			return
		}
		encPaylodBytes.Write(encPayloadBlock)
	}
	encPayloadData := struct {
		EncPayload []byte `json:"enc_payload"`
	}{
		EncPayload: encPaylodBytes.Bytes(),
	}

	if err = encryptedJsonSend(connWriter, tempCipher, encPayloadData); err != nil {
		log.Println(err)
		return
	}
	payloadBytes.Reset()
	encPaylodBytes.Reset()
}
