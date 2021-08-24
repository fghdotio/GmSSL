package gmms

/*
#include <stdlib.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
*/
import "C"

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"unsafe"
)

type CurveParams struct {
	*elliptic.CurveParams

	curve *C.EC_GROUP
}

func NewSM2Curve() {
	sm2Curve := newCurve(C.NID_sm2p256v1)
	if sm2Curve == nil {
		panic("sm2Curve == nil")
	}
	var sm2CurveParams CurveParams
	sm2CurveParams.curve = sm2Curve
	sm2CurveParams.CurveParams = buildCurveParams(sm2Curve)
	fmt.Println(sm2CurveParams.CurveParams)
}

func newCurve(nid C.int) *C.EC_GROUP {
	curve := C.EC_GROUP_new_by_curve_name(nid)
	if curve == nil {
		panic("new curve error")
	}
	return curve
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

	if C.EC_GROUP_get_curve_GFp(curve, p, a, b, nil) != 1 {
		panic("EC_GROUP_get_curve_GFp error")
	}
	if p == nil || a == nil || b == nil {
		panic("something went wrong getting GFp params")
	}
	cp.P, _ = new(big.Int).SetString(C.GoString(C.BN_bn2dec(p)), 10)
	cp.N, _ = new(big.Int).SetString(C.GoString(C.BN_bn2dec(a)), 10)
	cp.B, _ = new(big.Int).SetString(C.GoString(C.BN_bn2hex(b)), 16)

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

func GetAvailableCurves() {
	var availableCurves map[C.int]bool
	var (
		l  = C.size_t(1001)
		bi = make([]C.EC_builtin_curve, l)
		n  = int(C.EC_get_builtin_curves(&bi[0], l))
	)
	availableCurves = make(map[C.int]bool)
	for i := 0; i < n; i++ {
		availableCurves[bi[i].nid] = true
		fmt.Println(bi[i].nid)
	}
}

// func GetKeyType(priv *PrivateKey) {
// 	fmt.Println(C.EVP_PKEY_base_id(priv.pkey))
// 	fmt.Println(C.EVP_PKEY_id(priv.pkey))
// }

func ParseGroupFromPriv() {
	k, _ := GeneratePrivateKey("EC", [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}, nil)
	fmt.Println(buildCurveParams(C.EC_KEY_get0_group(C.EVP_PKEY_get0_EC_KEY(k.pkey))))
}

func ParseKey() (priv []byte, x, y *big.Int, err error) {
	kk, _ := GeneratePrivateKey("EC", [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}, nil)

	k := C.EVP_PKEY_get0_EC_KEY(kk.pkey)
	defer C.EC_KEY_free(k)
	blen := C.i2d_ECPrivateKey(k, nil)
	if blen == 0 {
		return nil, nil, nil, errors.New("can't get private key")
	}
	buf := C.malloc(C.size_t(blen))
	defer C.free(buf)
	pkey := (*C.uchar)(unsafe.Pointer(buf))
	if C.i2d_ECPrivateKey(k, &pkey) == 0 {
		return nil, nil, nil, errors.New("can't get private key")
	}

	point := C.EC_KEY_get0_public_key(k)
	if point == nil {
		return nil, nil, nil, errors.New("can't get public key")
	}
	defer C.EC_POINT_free(point)

	rx := C.BN_new()
	if rx == nil {
		return nil, nil, nil, errors.New("error creating big num")
	}
	defer C.BN_free(rx)
	ry := C.BN_new()
	if ry == nil {
		return nil, nil, nil, errors.New("errors creating big num")
	}
	defer C.BN_free(ry)

	d := C.BN_new()
	if d == nil {
		return nil, nil, nil, errors.New("errors creating big num")
	}
	defer C.BN_free(d)
	d = C.EC_KEY_get0_private_key(k)
	dd, _ := new(big.Int).SetString(C.GoString(C.BN_bn2hex(d)), 16)

	sm2Curve := newCurve(C.NID_sm2p256v1)
	if C.EC_POINT_get_affine_coordinates_GFp(sm2Curve, point, rx, ry, nil) != 1 {
		return nil, nil, nil, errors.New("can't get public key")
	}
	x, _ = new(big.Int).SetString(C.GoString(C.BN_bn2hex(rx)), 16)
	y, _ = new(big.Int).SetString(C.GoString(C.BN_bn2hex(ry)), 16)

	priv = C.GoBytes(unsafe.Pointer(pkey), C.int(blen))

	fmt.Println(priv, x, y, dd)
	return priv, x, y, nil
}
