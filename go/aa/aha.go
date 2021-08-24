package gmssl

/*
#include <stdlib.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

int copy_evp_pkey(const EVP_PKEY *pkey) {
	int ret;
	EVP_PKEY *pk_dup;
	ret = EVP_PKEY_copy_parameters(pk_dup, pkey);
	return ret;
}

int X_BIO_read(BIO *b, void *buf, int len) {
	return BIO_read(b, buf, len);
}

int X_BIO_write(BIO *b, const void *buf, int len) {
	return BIO_write(b, buf, len);
}

*/
import "C"
import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"unsafe"

	"github.com/hyperledger/fabric/crypto"
)

type anyBio C.BIO

func (b *anyBio) Read(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n = int(C.X_BIO_read((*C.BIO)(b), unsafe.Pointer(&buf[0]), C.int(len(buf))))
	if n <= 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (b *anyBio) Write(buf []byte) (written int, err error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n := int(C.X_BIO_write((*C.BIO)(b), unsafe.Pointer(&buf[0]),
		C.int(len(buf))))
	if n != len(buf) {
		return n, errors.New("BIO write failed")
	}
	return n, nil
}

func asAnyBio(b *C.BIO) *anyBio { return (*anyBio)(b) }

func ConvertPrivateKey(sk *PrivateKey) (*crypto.PrivateKey, error) {

	ret := C.copy_evp_pkey(sk.pkey)
	fmt.Println(int(ret))

	// defer C.EVP_PKEY_free(sk.pkey)

	k := C.EVP_PKEY_get0_EC_KEY(sk.pkey)
	defer C.EC_KEY_free(k)
	blen := C.i2d_ECPrivateKey(k, nil)
	if blen == 0 {
		return nil, fmt.Errorf("i2d_ECPrivateKey error")
	}
	buf := C.malloc(C.size_t(blen))
	defer C.free(buf)

	point := C.EC_KEY_get0_public_key(k)
	if point == nil {
		return nil, errors.New("can't get public key")
	}
	defer C.EC_POINT_free(point)

	// 椭圆曲线参数
	curveParams := buildCurveParams(C.EC_KEY_get0_group(C.EVP_PKEY_get0_EC_KEY(sk.pkey)))

	// 公钥
	rx := C.BN_new()
	if rx == nil {
		return nil, errors.New("error creating big num")
	}
	defer C.BN_free(rx)
	ry := C.BN_new()
	if ry == nil {
		return nil, errors.New("errors creating big num")
	}
	defer C.BN_free(ry)
	if C.EC_POINT_get_affine_coordinates_GFp(C.EC_KEY_get0_group(C.EVP_PKEY_get0_EC_KEY(sk.pkey)), point, rx, ry, nil) != 1 {
		return nil, errors.New("can't get public key")
	}
	x, _ := new(big.Int).SetString(C.GoString(C.BN_bn2hex(rx)), 16)
	y, _ := new(big.Int).SetString(C.GoString(C.BN_bn2hex(ry)), 16)

	// 私钥
	dd := C.BN_new()
	if dd == nil {
		return nil, errors.New("errors creating big num")
	}
	defer C.BN_free(dd)
	dd = C.EC_KEY_get0_private_key(k)
	d, _ := new(big.Int).SetString(C.GoString(C.BN_bn2hex(dd)), 16)

	return &crypto.PrivateKey{
		PublicKey: crypto.PublicKey{
			Curve: curveParams,
			X:     x,
			Y:     y,
		},
		D: d,
	}, nil
}

func ConvertPublicKey(pk *PublicKey) (*crypto.PublicKey, error) {
	k := C.EVP_PKEY_get0_EC_KEY(pk.pkey)
	point := C.EC_KEY_get0_public_key(k)
	if point == nil {
		return nil, errors.New("can't get public key here")
	}
	defer C.EC_POINT_free(point)

	// 椭圆曲线参数
	curveParams := buildCurveParams(C.EC_KEY_get0_group(C.EVP_PKEY_get0_EC_KEY(pk.pkey)))

	// 公钥
	rx := C.BN_new()
	if rx == nil {
		return nil, errors.New("error creating big num")
	}
	defer C.BN_free(rx)
	ry := C.BN_new()
	if ry == nil {
		return nil, errors.New("errors creating big num")
	}
	defer C.BN_free(ry)
	if C.EC_POINT_get_affine_coordinates_GFp(C.EC_KEY_get0_group(C.EVP_PKEY_get0_EC_KEY(pk.pkey)), point, rx, ry, nil) != 1 {
		return nil, errors.New("can't get public key there")
	}
	x, _ := new(big.Int).SetString(C.GoString(C.BN_bn2hex(rx)), 16)
	y, _ := new(big.Int).SetString(C.GoString(C.BN_bn2hex(ry)), 16)
	return &crypto.PublicKey{
		Curve: curveParams,
		X:     x,
		Y:     y,
	}, nil
}

func buildCurveParams(curve *C.EC_GROUP) *elliptic.CurveParams {
	cp := &elliptic.CurveParams{}
	elem := reflect.ValueOf(cp).Elem()
	f := elem.FieldByName("Name")
	if f.IsValid() {
		f.SetString(getCurveName(curve))
	}
	cp.BitSize = getCurveBitSize(curve)

	p := C.BN_new()
	if p == nil {
		panic("p == nil")
	}
	defer C.BN_free(p)
	a := C.BN_new()
	if a == nil {
		panic("a == nil")
	}
	defer C.BN_free(a)
	b := C.BN_new()
	if b == nil {
		panic("b == nil")
	}
	defer C.BN_free(b)
	n := C.BN_new()
	if n == nil {
		panic("n == nil")
	}
	defer C.BN_free(n)

	if C.EC_GROUP_get_curve_GFp(curve, p, a, b, nil) != 1 {
		panic("EC_GROUP_get_curve_GFp error")
	}
	if p == nil || a == nil || b == nil {
		panic("something went wrong getting GFp params")
	}
	cp.P, _ = new(big.Int).SetString(C.GoString(C.BN_bn2dec(p)), 10)
	cp.B, _ = new(big.Int).SetString(C.GoString(C.BN_bn2hex(b)), 16)
	// aa, _ := new(big.Int).SetString(C.GoString(C.BN_bn2dec(a)), 10) // 实际是 a
	n = C.EC_GROUP_get0_order(curve)
	cp.N, _ = new(big.Int).SetString(C.GoString(C.BN_bn2hex(n)), 16)

	generator := C.EC_GROUP_get0_generator(curve)
	if generator == nil {
		panic("generator cannot be nil")
	}
	x := C.BN_new()
	if x == nil {
		panic("x == l")
	}
	defer C.BN_free(x)
	y := C.BN_new()
	if y == nil {
		panic("y == nil")
	}
	defer C.BN_free(y)
	if C.EC_POINT_get_affine_coordinates_GFp(curve, generator, x, y, nil) != 1 {
		panic("EC_POINT_get_affine_coordinates_GFp error")
	}
	if x == nil || y == nil {
		panic("something went wrong getting affine coordinates")
	}
	cp.Gx, _ = new(big.Int).SetString(C.GoString(C.BN_bn2hex(x)), 16)
	cp.Gy, _ = new(big.Int).SetString(C.GoString(C.BN_bn2hex(y)), 16)

	return cp
}

func getCurveName(curve *C.EC_GROUP) string {
	return C.GoString(C.OBJ_nid2sn(C.EC_GROUP_get_curve_name(curve)))
}

func getCurveBitSize(curve *C.EC_GROUP) int {
	return int(C.EC_GROUP_get_degree(curve))
}

func newCurve(nid C.int) *C.EC_GROUP {
	curve := C.EC_GROUP_new_by_curve_name(nid)
	if curve == nil {
		panic("new curve error")
	}
	return curve
}
