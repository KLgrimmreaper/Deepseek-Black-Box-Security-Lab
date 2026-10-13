# test certificates

these are throwaway certificates for the local fake target in `fake_target.py`. they exist so the
https tests can run without a network, a docker container or an extra python package.

- `ca.pem` is a self signed test certificate authority
- `server.pem` and `server-key.pem` are a server certificate and key signed by it, with
  `subjectAltName = IP:127.0.0.1, DNS:localhost`

they are not secrets and they must never be trusted outside this test folder. the ca is only ever
passed to the runner as `CA_BUNDLE` inside a test, and the private key only exists so the fake
target can serve tls on localhost.

the test ca private key is deliberately not committed. to regenerate all three files:

```powershell
$ssl = "C:\Program Files\Git\usr\bin\openssl.exe"
$tmp = Join-Path $env:TEMP "dsh-certs"; New-Item -ItemType Directory -Force $tmp | Out-Null
& $ssl req -x509 -newkey rsa:2048 -nodes -keyout "$tmp\ca-key.pem" -out ca.pem -days 3650 -subj "/CN=dsh lab test ca"
& $ssl req -newkey rsa:2048 -nodes -keyout server-key.pem -out "$tmp\server.csr" -subj "/CN=127.0.0.1"
Set-Content "$tmp\ext.cnf" "subjectAltName=IP:127.0.0.1,DNS:localhost"
& $ssl x509 -req -in "$tmp\server.csr" -CA ca.pem -CAkey "$tmp\ca-key.pem" -CAcreateserial -out server.pem -days 3650 -extfile "$tmp\ext.cnf"
```

the certificates expire in 10 years, after which the tests would start failing with a verification
error and this command would need running again.
