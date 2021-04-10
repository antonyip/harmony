package bls_interface

// "github.com/harmony-one/harmony/crypto/bls_interface"
import (
	"bytes"
	"encoding/hex"
	//"math/big"
	"fmt"
	blst "github.com/supranational/blst/bindings/go"
	"github.com/pkg/errors"
)

func hex2byte(s string) ([]byte, error) {
if (len(s) & 1) == 1 {
	return nil, fmt.Errorf("odd length")
}
return hex.DecodeString(s)
}

type blstPublicKey struct {
	publicKey blst.P1Affine
}

type blstSecretKey struct {
	secretKey blst.SecretKey
}

type blstSign struct {
	sign blst.P2Affine
}

func (pub *blstPublicKey) SerializeToHexStr() string {
	return "hellooworld"
}

func (pub* blstPublicKey) DeserializeHexStr(str string) error {
	return errors.New("Public key is nil.")
}

func (pub *blstPublicKey) Serialize() []byte {
	var buf bytes.Buffer
	return buf.Bytes()
}

func (pub *blstPublicKey) Deserialize(buf []byte) error {
	return errors.New("Public key is nil.")
}
