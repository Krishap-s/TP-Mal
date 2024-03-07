package main

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

var (
	pubKeyBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIqnQpX0arufowZEfxbGaFA+0GTg+pZb86WNqrqAyIADOADEVvq3ehK6W9oybQSQ1ve9e+jyoSrjRU3l1fJBO6A=="
	ip           = "127.0.0.1"
	port         = 7331
)

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
	thetpm, err := transport.OpenTPM()
	if err != nil {
		log.Fatalf("Failed to open tpm: %v", err)
	}
	defer func() {
		if err := thetpm.Close(); err != nil {
			log.Fatalf("Failed to close tpm: %v", err)
		}
	}()
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
		log.Fatalf("could not create the TPM key: %v", err)
	}

	outPub, err := tpmCreateRsp.OutPublic.Contents()
	if err != nil {
		log.Fatalf("%v", err)
	}
	tpmPub, err := outPub.Unique.ECC()
	if err != nil {
		log.Fatalf("%v", err)
	}
	//	tpmX := big.NewInt(0).SetBytes(tpmPub.X.Buffer)
	//	tpmY := big.NewInt(0).SetBytes(tpmPub.Y.Buffer)
	// Connect to server
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		log.Panicf("Unable to connect to server: %v", err)
	}
	defer func() {
		conn.Close()
	}()
	conn.Write(tpmPub.X.Buffer)
	conn.Write(tpmPub.Y.Buffer)
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
	log.Printf("ECDH X: %v", outPointTPM.X.Buffer)
	_, err = aes.NewCipher(outPointTPM.X.Buffer)
	if err != nil {
		log.Panicf("Error creating cipher: %v", err)
	}
	// Get random value from TPM
}
