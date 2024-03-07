Create ECC private key:
```bash
openssl ecparam -name prime256v1 -genkey -noout -out private.ec.key
openssl pkcs8 -topk8 -in private.ec.key -out private.pem -nocrypt
openssl ec -in private.pem -pubout -out public.pem
openssl base64 -d -in public.pem -out public.der
```