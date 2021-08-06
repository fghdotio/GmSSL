package gmms

import (
	"bytes"
	"fmt"
	"testing"
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

func TestSM2GenSignVerify(t *testing.T) {
	// SM2 key pair operations
	sm2KeyGenArgs := [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}
	sm2sk, err := GeneratePrivateKey("EC", sm2KeyGenArgs, nil)
	if err != nil {
		t.Fatal(err)
	}

	// sm2skString, err := sm2sk.GetText()
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// fmt.Printf("sm2 private string (with both private key and public key):\n%s\n\n", sm2skString)
	sm2skPEM, err := sm2sk.GetPEM("SMS4", "password")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("sm2 encrypted private key pem:\n%s\n", sm2skPEM)
	sm2pkPEM, err := sm2sk.GetPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("sm2 public key pem:\n%s\n", sm2pkPEM)

	sm2pk, err := NewPublicKeyFromPEM(sm2pkPEM)
	if err != nil {
		t.Fatal(err)
	}
	// sm2pkString, err := sm2pk.GetText()
	// if err != nil {
	// 	t.Fatal(err)
	// }
	sm2pkPEMcopy, err := sm2pk.GetPEM()
	if err != nil {
		t.Fatal(err)
	}
	// fmt.Println(sm2pkString)
	if sm2pkPEMcopy != sm2pkPEM {
		t.Fatal("public key not identical")
	}

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
