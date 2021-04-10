package bls_interface

// "github.com/harmony-one/harmony/crypto/bls_interface"
import (
	//"bytes"
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
	if pub == nil {
		return ""
	}
	return hex.EncodeToString(pub.publicKey.Serialize())
}

func (pub* blstPublicKey) DeserializeHexStr(str string) error {
	if pub == nil {
		return errors.New("Public key is nil.")
	}
	a, err := hex2byte(str)
	if err != nil {
		return err
	}
	pub.publicKey.Deserialize(a)
	return nil
}

func (pub *blstPublicKey) Serialize() []byte {
	return pub.publicKey.Serialize()
}

func (pub *blstPublicKey) Deserialize(buf []byte) error {
	if pub == nil {
		return errors.New("Public key is nil.")
	}
	if len(buf) == 0 {
		return errors.New("Empty bytes")
	}
	
	pub.publicKey.Deserialize(buf)
	return nil
}

func (pub* blstPublicKey) Add(rhs *blstPublicKey) {
	if pub == nil || rhs == nil {
		return
	}
	// not sure how to map this too.
}

func (pub* blstPublicKey) Sub(rhs *blstPublicKey) {
	//?? not sure where this goes
}
func (pub *blstPublicKey) GetAddress() [20]byte {
	address := [20]byte{}
	hash := sha256.Sum256(pub.publicKey.Serialize())
	copy(address[:], hash[:20])
	return address
}
func (pub *blstPublicKey) IsEqual(rhs *blstPublicKey) bool {
	return pub.publicKey.Equals(rhs.publicKey);
}