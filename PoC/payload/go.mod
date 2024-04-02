module poc_payload

go 1.21

require (
	github.com/google/go-attestation v0.5.1
	github.com/google/go-tpm v0.9.0
)

require (
	github.com/google/certificate-transparency-go v1.1.2 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/traefik/yaegi v0.16.0 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/sys v0.16.0 // indirect
)

replace github.com/google/go-attestation => ../../../go-attestation/
