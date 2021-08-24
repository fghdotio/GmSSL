package gmssl

import (
	"fmt"
	"os"
	"testing"

	"github.com/hyperledger/fabric/crypto"

	"github.com/hyperledger/fabric/x509/gmsm"
)

func TestParseGMSSLKey(t *testing.T) {
	sm2sk, err := GeneratePrivateKey("EC", [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := GetPrivateKeyDER(sm2sk)
	if err != nil {
		t.Fatal(err)
	}
	parsedPrivKey, err := gmsm.NewX509().ParsePKCS8PrivateKey(privDER)
	if err != nil {
		t.Fatal(err)
	}
	sk, ok := parsedPrivKey.(*crypto.PrivateKey)
	if !ok {
		t.Fatal("err")
	}
	fmt.Printf("X: %x\nY: %x\nD: %x\n", sk.X, sk.Y, sk.D)
	fmt.Printf("\nP: %x\n", sk.Params().P)
	fmt.Printf("B: %x\n", sk.Params().B)
	fmt.Printf("Gx: %x\n", sk.Params().Gx)
	fmt.Printf("Gy: %x\n", sk.Params().Gy)
	fmt.Printf("N: %x\n", sk.Params().N) // 不同
	fmt.Printf("Name: %s\n", sk.Params().Name)
	fmt.Printf("BitSize: %x\n\n", sk.Params().BitSize)

	sm2pk, err := sm2sk.GetPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pkDER, err := GetPublicKeyDER(sm2pk)
	if err != nil {
		t.Fatal(err)
	}
	// fmt.Printf("pk DER:\n%v\n", pkDER)
	parsedPubKey, err := gmsm.NewX509().ParsePKIXPublicKey(pkDER)
	if err != nil {
		t.Fatal(err)
	}
	pk, ok := parsedPubKey.(*crypto.PublicKey)
	if !ok {
		t.Fatal("err")
	}
	fmt.Printf("X: %x\nY: %x\n", pk.X, pk.Y)
	fmt.Printf("\nP: %x\n", pk.Params().P)
	fmt.Printf("B: %x\n", pk.Params().B)
	fmt.Printf("Gx: %x\n", pk.Params().Gx)
	fmt.Printf("Gy: %x\n", pk.Params().Gy)
	fmt.Printf("N: %x\n", pk.Params().N) // 不同
	fmt.Printf("Name: %s\n", pk.Params().Name)
	fmt.Printf("BitSize: %x\n", pk.Params().BitSize)
}

func TestParsePublicKey(t *testing.T) {
	sm2sk, err := GeneratePrivateKey("EC", [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := GetPrivateKeyDER(sm2sk)
	if err != nil {
		t.Fatal(err)
	}
	parsedPrivKey, err := gmsm.NewX509().ParsePKCS8PrivateKey(privDER)
	if err != nil {
		t.Fatal(err)
	}
	sk, ok := parsedPrivKey.(*crypto.PrivateKey)
	if !ok {
		t.Fatal("err")
	}
	fmt.Printf("X: %x\nY: %x\nD: %x\n", sk.X, sk.Y, sk.D)
	fmt.Printf("\nP: %x\n", sk.Params().P)
	fmt.Printf("B: %x\n", sk.Params().B)
	fmt.Printf("Gx: %x\n", sk.Params().Gx)
	fmt.Printf("Gy: %x\n", sk.Params().Gy)
	fmt.Printf("N: %x\n", sk.Params().N) // 不同
	fmt.Printf("Name: %s\n", sk.Params().Name)
	fmt.Printf("BitSize: %x\n", sk.Params().BitSize)
}

func TestGetKeyDER(t *testing.T) {
	sm2sk, err := GeneratePrivateKey("EC", [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sm2pk, err := sm2sk.GetPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pkDER, err := GetPublicKeyDER(sm2pk)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("pk DER:\n%v\n", pkDER)
	parsedPubKey, err := gmsm.NewX509().ParsePKIXPublicKey(pkDER)
	if err != nil {
		t.Fatal(err)
	}
	pk, ok := parsedPubKey.(*crypto.PublicKey)
	if !ok {
		t.Fatal("err")
	}
	fmt.Printf("X: %x\nY: %x\n", pk.X, pk.Y)
	fmt.Printf("\nP: %x\n", pk.Params().P)
	fmt.Printf("B: %x\n", pk.Params().B)
	fmt.Printf("Gx: %x\n", pk.Params().Gx)
	fmt.Printf("Gy: %x\n", pk.Params().Gy)
	fmt.Printf("N: %x\n", pk.Params().N) // 不同
	fmt.Printf("Name: %s\n", pk.Params().Name)
	fmt.Printf("BitSize: %x\n", pk.Params().BitSize)
}

func TestConvertKey(t *testing.T) {
	sm2sk, err := GeneratePrivateKey("EC", [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// sm2pk, err := sm2sk.GetPublicKey()
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// pk, err := ConvertPublicKey(sm2pk)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	sk, err := ConvertPrivateKey(sm2sk)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("X: %x\nY: %x\nD: %x\n", sk.X, sk.Y, sk.D)
	fmt.Printf("\nP: %x\n", sk.Params().P)
	fmt.Printf("B: %x\n", sk.Params().B)
	fmt.Printf("Gx: %x\n", sk.Params().Gx)
	fmt.Printf("Gy: %x\n", sk.Params().Gy)
	fmt.Printf("N: %x\n", sk.Params().N) // 不同
	fmt.Printf("Name: %s\n", sk.Params().Name)
	fmt.Printf("BitSize: %x\n", sk.Params().BitSize)

	// https: //www.oscca.gov.cn/sca/xxgk/2010-12/17/content_1002386.shtml

	// fmt.Printf("X: %x\nY: %x\n", pk.X, pk.Y)
	// fmt.Printf("\nP: %x\n", pk.Params().P)
	// fmt.Printf("B: %x\n", pk.Params().B)
	// fmt.Printf("Gx: %x\n", pk.Params().Gx)
	// fmt.Printf("Gy: %x\n", pk.Params().Gy)
	// fmt.Printf("N: %x\n", pk.Params().N) // 不同
	// fmt.Printf("Name: %s\n", pk.Params().Name)
	// fmt.Printf("BitSize: %x\n", pk.Params().BitSize)
}

func TestSaveLoadKeyAsPEM(t *testing.T) {
	tmpSKFile, tmpPKFile := "./tmp_sk.pem", "./tmp_pk.pem"
	sm2sk, err := GeneratePrivateKey("EC", [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = SavePrivateKeyAsPEM(tmpSKFile, sm2sk, nil)
	if err != nil {
		t.Fatal(err)
	}
	sm2pk, err := sm2sk.GetPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = SavePublicKeyAsPEM(tmpPKFile, sm2pk)
	if err != nil {
		t.Fatal(err)
	}
	_, err = LoadPublicKeyFromPEM(tmpPKFile)
	if err != nil {
		t.Fatal(err)
	}
	_, err = LoadPrivateKeyFromPEM(tmpSKFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(tmpSKFile)
	os.Remove(tmpPKFile)
}
