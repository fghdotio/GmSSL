package gmssl

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"unsafe"

	"encoding/pem"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/hyperledger/fabric/crypto"
	"github.com/hyperledger/fabric/gm/gmsm"
	gmsmX509 "github.com/hyperledger/fabric/x509/gmsm"
)

func TestSM3(t *testing.T) {
	// SM3 digest with GM-SSL Go API
	sm3Ctx, err := NewDigestContext("SM3")
	if err != nil {
		t.Fatal(err)
	}

	if err := sm3Ctx.Update([]byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := sm3Ctx.Update([]byte("bc")); err != nil {
		t.Fatal(err)
	}
	sm3Digest, err := sm3Ctx.Final()
	if err != nil {
		t.Fatal(err)
	}

	// SM3 digest with Go hash.Hash API
	sm3Hash := New()
	_, err = sm3Hash.Write([]byte("abc"))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sm3Digest, sm3Hash.Sum(nil)) {
		t.Fatal("sm3 error")
	}
	t.Logf("sm3(\"abc\") = %x\n", sm3Digest)
}

func TestKeyGen(t *testing.T) {
	sm2KeyGenArgs := [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}
	sm2sk, err := GeneratePrivateKey("EC", sm2KeyGenArgs, nil)
	if err != nil {
		t.Fatal(err)
	}
	sm2pk, err := sm2sk.GetPublicKey()
	if err != nil {
		t.Fatal(err)
	}

	sm2pkString, err := sm2pk.GetText()
	if err != nil {
		t.Fatal(err)
	}

	sm2pkPEM, err := sm2sk.GetPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	sm2pkAlt, err := NewPublicKeyFromPEM(sm2pkPEM)
	if err != nil {
		t.Fatal(err)
	}
	sm2pkStringAlt, err := sm2pkAlt.GetText()
	if err != nil {
		t.Fatal(err)
	}
	if sm2pkString != sm2pkStringAlt {
		t.Fatal("TestPublicKeyGen error")
	}
}

func TestSM2SignVerify(t *testing.T) {
	// SM2 key pair operations
	sm2KeyGenArgs := [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}
	sm2sk, err := GeneratePrivateKey("EC", sm2KeyGenArgs, nil)
	if err != nil {
		t.Fatal(err)
	}

	sm2skString, err := sm2sk.GetText()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("sm2 private string (with both private key and public key):\n%s\n\n", sm2skString)
	sm2skPEM, err := sm2sk.GetPEM("", "")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("sm2 private key pem:\n%s\n", sm2skPEM)
	sm2pkPEM, err := sm2sk.GetPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("sm2 public key pem:\n%s\n", sm2pkPEM)

	sm2pk, err := NewPublicKeyFromPEM(sm2pkPEM)
	if err != nil {
		t.Fatal(err)
	}

	sm2pkString, err := sm2pk.GetText()
	if err != nil {
		t.Fatal(err)
	}
	sm2pkPEMcopy, err := sm2pk.GetPEM()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("sm2 public key string", sm2pkString)
	if sm2pkPEMcopy != sm2pkPEM {
		t.Fatal("public key not identical")
	}
	// block, _ := pem.Decode([]byte(sm2pkPEM))
	// if block == nil {
	// 	t.Fatal("BIO_new_mem_buf")
	// }
	// fmt.Printf("%#v\n", block)
	// cert, err := sm2.ParseCertificate(block.Bytes)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// fmt.Printf("cert: %#v\n", cert)

	// SM2 sign/verification
	// #define SM2_DEFAULT_ID_GMT09			"1234567812345678"
	z, err := sm2pk.ComputeSM2IDDigest("1234567812345678")
	if err != nil {
		t.Fatal(err)
	}
	sm3Ctx, err := NewDigestContext("SM3")
	if err != nil {
		t.Fatal(err)
	}
	// sm3Ctx.Reset()
	if err := sm3Ctx.Update(z); err != nil {
		t.Fatal(err)
	}
	if err := sm3Ctx.Update([]byte("hhhh")); err != nil {
		t.Fatal(err)
	}
	digest, err := sm3Ctx.Final()
	if err != nil {
		t.Fatal(err)
	}

	sig, err := sm2sk.Sign("sm2sign", digest, nil)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("sm2sign(sm3(\"hhhh\")) = %x\n", sig)

	if err := sm2pk.Verify("sm2sign", digest, sig, nil); err != nil {
		t.Fatal(err)
	}
}

func TestParseCertificate(t *testing.T) {
	certPEM := `-----BEGIN CERTIFICATE-----
MIICAjCCAaigAwIBAgIBATAKBggqgRzPVQGDdTBSMQswCQYDVQQGEwJDTjELMAkG
A1UECAwCQkoxCzAJBgNVBAcMAkJKMQwwCgYDVQQKDANQS1UxCzAJBgNVBAsMAkNB
MQ4wDAYDVQQDDAVQS1VDQTAeFw0xNzA2MDEwMDAwMDBaFw0yMDA2MDEwMDAwMDBa
MEYxCzAJBgNVBAYTAkNOMQswCQYDVQQIDAJCSjEMMAoGA1UECgwDUEtVMQswCQYD
VQQLDAJDQTEPMA0GA1UEAwwGYW50c3NzMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0D
QgAEHpXtrYNlwesl7IyPuaHKKHqn4rHBk+tCU0l0T+zuBNMHAOJzKNDbobno6gOI
EQlVfC9q9uk9lO174GJsMLWJJqN7MHkwCQYDVR0TBAIwADAsBglghkgBhvhCAQ0E
HxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFJsrRYOA
J8gpNq0KK6yuh/Dv9SjaMB8GA1UdIwQYMBaAFH1Dhf9CqQQYHF/8euzcPROIzn0r
MAoGCCqBHM9VAYN1A0gAMEUCIQCjrQ2nyiPqod/gZdj5X1+WW4fGtyqXvXLL3lOF
31nA/gIgZOpHLnvkyggY9VFfEQVp+8t6kewSfxb4eOImSu+dZcE=
-----END CERTIFICATE-----`

	cert, _ := NewCertificateFromPEM(certPEM, "")
	subject, _ := cert.GetSubject()
	issuer, _ := cert.GetIssuer()
	serial, _ := cert.GetSerialNumber()
	certPubKey, _ := cert.GetPublicKey()
	certPubKeyString, _ := certPubKey.GetText()
	certString, _ := cert.GetText()

	fmt.Println("Certificate:")
	fmt.Printf("  Subject = %s\n", subject)
	fmt.Printf("  Issuer = %s \n", issuer)
	fmt.Printf("  Serial Number = %s\n", serial)
	fmt.Println(certPubKeyString)
	fmt.Println(certString)
}

func TestEncryptDecrypt(t *testing.T) {
	// Generate random key and IV
	keyLen, _ := GetCipherKeyLength("SMS4")
	key, _ := GenerateRandom(keyLen)
	ivLen, _ := GetCipherIVLength("SMS4")
	iv, _ := GenerateRandom(ivLen)

	// SMS4-CBC Encrypt/Decrypt
	encryptor, _ := NewCipherContext("SMS4", key, iv, true)
	ciphertext1, _ := encryptor.Update([]byte("hello"))
	ciphertext2, _ := encryptor.Final()
	ciphertext := make([]byte, 0, len(ciphertext1)+len(ciphertext2))
	ciphertext = append(ciphertext, ciphertext1...)
	ciphertext = append(ciphertext, ciphertext2...)

	decryptor, _ := NewCipherContext("SMS4", key, iv, false)
	plaintext1, _ := decryptor.Update(ciphertext)
	plaintext2, _ := decryptor.Final()
	plaintext := make([]byte, 0, len(plaintext1)+len(plaintext2))
	plaintext = append(plaintext, plaintext1...)
	plaintext = append(plaintext, plaintext2...)

	fmt.Printf("sms4(\"%s\") = %x\n", plaintext, ciphertext)
	fmt.Println()
}

func TestSign(t *testing.T) {
	k, err := getPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	sk, ok := k.(*PrivateKey)
	if !ok {
		t.Fatal("not ok")
	}
	pk2, err := sk.GetPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(pk2)

	bss, err := NewSm2().Sign(sk, rand.Reader, []byte("hello"), nil)
	// bss, err := sk.Sign("sm2sign", []byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(bss)
}

func getPrivateKey() (interface{}, error) {
	bs, err := ioutil.ReadFile("/home/ubuntu/go/src/github.com/hyperledger/fabric-samples/test-network-simple/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp/keystore/c165c3dbe0809ace47de9709a99167728c9b1f4098037e5b02f75d5a70139955_sk")
	if err != nil {
		return nil, err
	}
	// fmt.Println(string(bs))
	sk, err := NewPrivateKeyFromPEM(string(bs), "")
	if err != nil {
		return nil, err
	}
	return sk, nil
}

func TestCrossSignVerify(t *testing.T) {
	skFile := "/home/ubuntu/go/src/github.com/hyperledger/fabric-samples/test-network-simple/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp/keystore/af366d1d06f97165be19ce6f76a2cece8a65620923537c621beaf21f8fde1ff2_sk"
	pkFile := "/home/ubuntu/go/src/github.com/hyperledger/fabric-samples/test-network-simple/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp/signcerts/peer0.org1.example.com-cert.pem"

	// gmssl 库解析出私钥
	skBs, err := ioutil.ReadFile(skFile)
	if err != nil {
		t.Fatal(err)
	}
	gmsslSk, err := NewPrivateKeyFromPEM(string(skBs), "")
	if err != nil {
		t.Fatal(err)
	}
	gmsslSig, err := NewSm2().Sign(gmsslSk, rand.Reader, []byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	// gmsm 解析公钥
	certBs, err := ioutil.ReadFile(pkFile)
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := pem.Decode(certBs)
	if pb == nil {
		t.Fatal("pem block is nil")
	}
	cert, err := gmsmX509.NewX509().ParseCertificate(pb.Bytes)
	var pk *crypto.PublicKey
	switch pkimpl := cert.PublicKey.(type) {
	case *crypto.PublicKey:
		pk = pkimpl
	case *ecdsa.PublicKey:
		pk = (*crypto.PublicKey)(unsafe.Pointer(pkimpl))
	default:
		t.Fatal("bad public key")
	}
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(gmsm.NewSm2().Verify(pk, []byte("hello"), gmsslSig))

	// gmsm 库解析出私钥
	gmsmSk, err := gmsm.LoadPrivateKeyFromPem(skFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	gmsmSig, err := gmsm.NewSm2().Sign(gmsmSk, rand.Reader, []byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	pkDER, err := gmsmX509.NewX509().MarshalPKIXPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	gmsslPk, err := LoadPublicKeyFromDER(pkDER)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(NewSm2().Verify(gmsslPk, []byte("hello"), gmsmSig))
}
