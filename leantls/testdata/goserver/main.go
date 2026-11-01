// Command goserver is the crypto/tls peer for the leantls interop tests.
//
// It prints one line, "<addr> <hex key>", and then serves until killed. The
// key is the server's Ed25519 key (pinned modes) or the CA's key (chain mode).
//
//	echo13     TLS 1.3 only, Ed25519 self-signed, echo
//	alpn13     as echo13, with ALPN: h2, then http/1.1
//	auth13     as echo13, asks for an optional client certificate (like APNs)
//	needauth13 as echo13, requires a client certificate
//	echo12     TLS 1.2 only, Ed25519 self-signed, echo
//	discard13  TLS 1.3, reads until EOF, then prints "result: <err|EOF>"
//	chain13    TLS 1.3, Ed25519 leaf for leantls.test signed by an Ed25519 CA
//	ecdsa13    TLS 1.3, ECDSA P-256 self-signed (not an Ed25519 peer)
//	x509ecdsa  TLS 1.3, the P-256 chain from <dir> (testdata/chain): leaf + inter
//	x509rsa    TLS 1.3, the RSA-2048 chain from <dir>; signs CertificateVerify with PSS
//	clientauth13 [bits]  TLS 1.3, Ed25519 self-signed like echo13, and requires a
//	           client certificate from its own CA (tls.RequireAndVerifyClientCert)
//	clientauth12 [bits]  TLS 1.2 only, like a RavenDB node on macOS (07-10-2026):
//	           ECDHE-RSA-AES128-GCM-SHA256 over P-256 only, an RSA-2048 server
//	           certificate for leantls.test under its own RSA CA, and a required
//	           client certificate as in clientauth13
//	echo12rsa [bits]     TLS 1.2 only, the same suite and curve, an RSA server
//	           certificate of [bits] (default 2048) under its own RSA CA, echo
//	record12   no server: prints one TLS 1.2 AES-128-GCM record (RFC 5288)
//	           with a fixed key, IV and sequence number, and exits
//	prf12      no server: prints P_SHA256 (RFC 5246 section 5) for the
//	           well-known test vector, from crypto/hmac, and exits
//
// The x509 modes take the chain directory as a second argument and print a
// zero key: the caller trusts the root from the same directory.
//
// clientauth13 makes an RSA client key of [bits] (default 2048) with a
// certificate under that CA, and prints a second line: "<hex PKCS#8 key>
// <hex DER client certificate>". The client proves itself with those.
// clientauth12 prints the same second line with a third field, the server's
// CA as hex DER; echo12rsa prints only that CA on its second line.
package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"
)

func cert(tmpl, parent *x509.Certificate, pub, signer any) []byte {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		panic(err)
	}
	return der
}

func template(serial int64, cn string, ca bool) *x509.Certificate {
	t := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"leantls.test"},
	}
	if ca {
		t.IsCA = true
		t.KeyUsage = x509.KeyUsageCertSign
		t.BasicConstraintsValid = true
		t.DNSNames = nil
	}
	return t
}

// clientCA makes a client CA and an RSA client key of the bits in the
// second argument (default 2048) with a certificate under it. It returns the
// pool for the server and the line for the test: "<hex PKCS#8> <hex DER>".
func clientCA() (*x509.CertPool, string) {
	caPub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	caT := template(2, "leantls client CA", true)
	caDER := cert(caT, caT, caPub, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	ck, err := rsa.GenerateKey(rand.Reader, bitsArg())
	if err != nil {
		panic(err)
	}
	ct := template(3, "leantls client", false)
	ct.DNSNames = nil
	ct.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	ct.KeyUsage = x509.KeyUsageDigitalSignature
	clientDER := cert(ct, ca, &ck.PublicKey, caKey)
	pk8, err := x509.MarshalPKCS8PrivateKey(ck)
	if err != nil {
		panic(err)
	}
	return pool, hex.EncodeToString(pk8) + " " + hex.EncodeToString(clientDER)
}

// bitsArg is the RSA size from the second argument, 2048 without one.
func bitsArg() int {
	if len(os.Args) > 2 {
		bits, err := strconv.Atoi(os.Args[2])
		if err != nil {
			panic(err)
		}
		return bits
	}
	return 2048
}

// rsaServer makes an RSA CA and an RSA leaf for leantls.test of the given
// size under it. It returns the chain (leaf only, as many servers send it),
// the leaf key and the CA as DER.
func rsaServer(bits int) ([][]byte, crypto.PrivateKey, []byte) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	caT := template(10, "leantls test RSA CA", true)
	caDER := cert(caT, caT, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	leaf := cert(template(11, "leantls.test", false), ca, &k.PublicKey, caKey)
	return [][]byte{leaf}, k, caDER
}

// record12 prints one TLS 1.2 application_data record sealed with
// AES-128-GCM as RFC 5288 and RFC 5246 6.2.3.3 describe it: nonce = fixed
// IV || explicit nonce (here the sequence number), AAD = seq || type ||
// version || plaintext length, record = header || explicit || ciphertext ||
// tag. The inputs are fixed; the Rust test uses the same.
func record12() {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	iv, _ := hex.DecodeString("a0a1a2a3")
	seq := []byte{0, 0, 0, 0, 0, 0, 0, 7}
	plain := []byte("leantls record12")
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := append(append([]byte{}, iv...), seq...)
	aad := append(append([]byte{}, seq...), 23, 3, 3, 0, byte(len(plain)))
	sealed := gcm.Seal(nil, nonce, plain, aad)
	n := len(seq) + len(sealed)
	rec := append([]byte{23, 3, 3, byte(n >> 8), byte(n)}, seq...)
	rec = append(rec, sealed...)
	fmt.Println(hex.EncodeToString(rec))
}

// prf12 prints 100 bytes of P_SHA256 for the TLS 1.2 PRF test vector that
// circulated on the IETF TLS list (secret 9bbe..., label "test label").
func prf12() {
	secret, _ := hex.DecodeString("9bbe436ba940f017b17652849a71db35")
	seed, _ := hex.DecodeString("a0ba9f936cda311827a6f796ffd5198c")
	labelSeed := append([]byte("test label"), seed...)
	mac := func(parts ...[]byte) []byte {
		h := hmac.New(sha256.New, secret)
		for _, p := range parts {
			h.Write(p)
		}
		return h.Sum(nil)
	}
	var out []byte
	for a := mac(labelSeed); len(out) < 100; a = mac(a) {
		out = append(out, mac(a, labelSeed)...)
	}
	fmt.Println(hex.EncodeToString(out[:100]))
}

func main() {
	mode := os.Args[1]
	var chain [][]byte
	var priv crypto.PrivateKey
	var shown []byte
	var curves []tls.CurveID
	var suites []uint16
	var clientCAs *x509.CertPool
	var clientLine string
	minV, maxV := uint16(tls.VersionTLS13), uint16(tls.VersionTLS13)

	switch mode {
	case "record12":
		record12()
		return
	case "prf12":
		prf12()
		return
	case "clientauth13":
		pub, k, _ := ed25519.GenerateKey(rand.Reader)
		t := template(1, "leantls-test", false)
		chain, priv, shown = [][]byte{cert(t, t, pub, k)}, k, pub
		clientCAs, clientLine = clientCA()
	case "clientauth12", "echo12rsa":
		// Zoals de RavenDB-node op macOS (07-10-2026): alleen 1.2, alleen
		// ECDHE-RSA-AES128-GCM-SHA256, alleen P-256.
		bits := 2048
		if mode == "echo12rsa" {
			bits = bitsArg()
		}
		var caDER []byte
		chain, priv, caDER = rsaServer(bits)
		shown = make([]byte, 32)
		minV, maxV = tls.VersionTLS12, tls.VersionTLS12
		curves = []tls.CurveID{tls.CurveP256}
		suites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
		if mode == "clientauth12" {
			clientCAs, clientLine = clientCA()
			clientLine += " " + hex.EncodeToString(caDER)
		} else {
			clientLine = hex.EncodeToString(caDER)
		}
	case "echo13", "echo12", "discard13", "echo13p256", "alpn13", "auth13", "needauth13":
		pub, k, _ := ed25519.GenerateKey(rand.Reader)
		t := template(1, "leantls-test", false)
		chain, priv, shown = [][]byte{cert(t, t, pub, k)}, k, pub
		if mode == "echo12" {
			minV, maxV = tls.VersionTLS12, tls.VersionTLS12
		}
		// echo13p256: een server zonder X25519, zoals prismic.io (07-10-2026).
		if mode == "echo13p256" {
			curves = []tls.CurveID{tls.CurveP256}
		}
	case "chain13":
		caPub, caKey, _ := ed25519.GenerateKey(rand.Reader)
		caT := template(1, "leantls test CA", true)
		caDER := cert(caT, caT, caPub, caKey)
		ca, _ := x509.ParseCertificate(caDER)
		pub, k, _ := ed25519.GenerateKey(rand.Reader)
		leaf := cert(template(2, "leantls.test", false), ca, pub, caKey)
		chain, priv, shown = [][]byte{leaf, caDER}, k, caPub
	case "ecdsa13":
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		t := template(1, "leantls-test", false)
		chain, priv, shown = [][]byte{cert(t, t, &k.PublicKey, k)}, k, make([]byte, 32)
	case "x509ecdsa", "x509rsa":
		dir, prefix := os.Args[2], "ecdsa"
		if mode == "x509rsa" {
			prefix = "rsa"
		}
		read := func(name string) []byte {
			b, err := os.ReadFile(dir + "/" + prefix + "-" + name)
			if err != nil {
				panic(err)
			}
			return b
		}
		blk, _ := pem.Decode(read("leaf.key"))
		if blk == nil {
			panic("no PEM in " + prefix + "-leaf.key")
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			panic(err)
		}
		chain, priv, shown = [][]byte{read("leaf.der"), read("inter.der")}, k, make([]byte, 32)
	default:
		panic("unknown mode " + mode)
	}

	cfg := &tls.Config{
		Certificates:     []tls.Certificate{{Certificate: chain, PrivateKey: priv}},
		MinVersion:       minV,
		MaxVersion:       maxV,
		CurvePreferences: curves,
		CipherSuites:     suites,
	}
	if clientCAs != nil {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = clientCAs
	}
	if mode == "alpn13" {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}
	if mode == "auth13" {
		cfg.ClientAuth = tls.RequestClientCert
	}
	if mode == "needauth13" {
		cfg.ClientAuth = tls.RequireAnyClientCert
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s %s\n", ln.Addr(), hex.EncodeToString(shown))
	if clientLine != "" {
		fmt.Println(clientLine)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			if mode == "discard13" {
				_, err := io.Copy(io.Discard, c)
				if err == nil || errors.Is(err, io.EOF) {
					fmt.Println("result: EOF")
				} else {
					fmt.Printf("result: %v\n", err)
				}
				return
			}
			io.Copy(c, c)
		}(c)
	}
}
