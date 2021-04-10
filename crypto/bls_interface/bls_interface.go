package bls_interface

// "github.com/harmony-one/harmony/crypto/bls_interface"
import (
	"bytes"
	"encoding/hex"
	"math/big"
	"github.com/harmony-one/bls/ffi/go/bls"
	"github.com/pkg/errors"
)

var (
	emptyBLSPubKey = SerializedPublicKey{}
	tmpDebugMode = 0
)

type BlsPublicKey struct {
	publicKey bls.PublicKey
	publicKeyNew blstPublicKey
}

func (pub *BlsPublicKey) SerializeToHexStr() string {
	if (tmpDebugMode == 1)	{
		return pub.publicKeyNew.SerializeToHexStr()
	} else {
		return pub.publicKey.SerializeToHexStr()
	}
}

func (pub* BlsPublicKey) DeserializeHexStr(str string) error {
	if (tmpDebugMode == 1)	{
		return pub.publicKeyNew.DeserializeHexStr(str)
	} else {
		return pub.publicKey.DeserializeHexStr(str)
	}
}

func (pub *BlsPublicKey) Serialize() []byte {
	if (tmpDebugMode == 1)	{
		return pub.publicKeyNew.Serialize()
	} else {
		return pub.publicKey.Serialize()
	}
}

func (pub *BlsPublicKey) Deserialize(buf []byte) error {
	if (tmpDebugMode == 1)	{
		return pub.publicKeyNew.Deserialize(buf)
	} else {
		return pub.publicKey.Deserialize(buf)
	}
}

func (pub* BlsPublicKey) Add(rhs *BlsPublicKey) {
	if (tmpDebugMode == 1)	{
		pub.publicKey.Add(&rhs.publicKey)
	} else {
		pub.publicKey.Add(&rhs.publicKey)
	}

}

func (pub* BlsPublicKey) Sub(rhs *BlsPublicKey) {
	if (tmpDebugMode == 1)	{
		pub.publicKey.Sub(&rhs.publicKey)
	} else {
		pub.publicKey.Sub(&rhs.publicKey)
	}

}

func (pub *BlsPublicKey) GetAddress() [20]byte {
	if (tmpDebugMode == 1)	{
		return pub.publicKey.GetAddress()
	} else {
		return pub.publicKey.GetAddress()
	}

}

func (pub *BlsPublicKey) IsEqual(rhs *BlsPublicKey) bool {
	if (tmpDebugMode == 1)	{
		return pub.publicKey.IsEqual(&rhs.publicKey)
	} else {
		return pub.publicKey.IsEqual(&rhs.publicKey)
	}
}

type BlsSecretKey struct {
	secretKey bls.SecretKey
	secretKeyNew blstSecretKey
}

func (sec *BlsSecretKey) SerializeToHexStr() string {
	if (tmpDebugMode == 1)	{
		return sec.secretKey.SerializeToHexStr()
	} else {
		return sec.secretKey.SerializeToHexStr()
	}
}

func (sec* BlsSecretKey) DeserializeHexStr(str string) error {
	if (tmpDebugMode == 1)	{
		return sec.secretKey.DeserializeHexStr(str)
	} else {
		return sec.secretKey.DeserializeHexStr(str)
	}
}

func (sec *BlsSecretKey) Deserialize(buf []byte) error {
	if (tmpDebugMode == 1)	{
		return sec.secretKey.Deserialize(buf)
	} else {
		return sec.secretKey.Deserialize(buf)
	}
}

func (sec *BlsSecretKey) IsEqual(rhs *BlsSecretKey) bool {
	if (tmpDebugMode == 1)	{
		return sec.secretKey.IsEqual(&rhs.secretKey)
	} else {
		return sec.secretKey.IsEqual(&rhs.secretKey)
	}
}

func (s *BlsSecretKey) Sign(m string) (sig *BlsSign) {
	returnValue := &BlsSign{}
	if (tmpDebugMode == 1)	{
		returnValue.sign.DeserializeHexStr(s.secretKey.Sign(m).SerializeToHexStr())
	} else {
		returnValue.sign.DeserializeHexStr(s.secretKey.Sign(m).SerializeToHexStr())
	}
	return returnValue
}

func (sec *BlsSecretKey) SignHash(hash []byte) (sig *BlsSign){
	returnValue := &BlsSign{}
	if (tmpDebugMode == 1)	{
		returnValue.sign.DeserializeHexStr(sec.secretKey.SignHash(hash).SerializeToHexStr())
	} else {
		returnValue.sign.DeserializeHexStr(sec.secretKey.SignHash(hash).SerializeToHexStr())
	}
	return returnValue
}

func (sec *BlsSecretKey) SetByCSPRNG() {
	if (tmpDebugMode == 1)	{
		sec.secretKey.SetByCSPRNG()
	} else {
		sec.secretKey.SetByCSPRNG()
	}
}

func (sec *BlsSecretKey) GetPublicKey() (pub *BlsPublicKey) {
	returnValue := &BlsPublicKey{}
	if (tmpDebugMode == 1)	{
		returnValue.DeserializeHexStr(sec.secretKey.GetPublicKey().SerializeToHexStr())
	} else {
		returnValue.DeserializeHexStr(sec.secretKey.GetPublicKey().SerializeToHexStr())
	}
	return returnValue
}

type BlsSign struct {
	sign bls.Sign
	signNew blstSign
}

func (sig* BlsSign) Add(rhs *BlsSign) {
	if (tmpDebugMode == 1)	{
		sig.sign.Add(&rhs.sign)
	} else {
		sig.sign.Add(&rhs.sign)
	}
}

func (sig *BlsSign) SerializeToHexStr() string {
	if (tmpDebugMode == 1)	{
		return sig.sign.SerializeToHexStr()
	} else {
		return sig.sign.SerializeToHexStr()
	}
}

func (sig* BlsSign) DeserializeHexStr(str string) error {
	if (tmpDebugMode == 1)	{
		return sig.sign.DeserializeHexStr(str)
	} else {
		return sig.sign.DeserializeHexStr(str)
	}
}

func (sig *BlsSign) Serialize() []byte {
	if (tmpDebugMode == 1)	{
		return sig.sign.Serialize()
	} else {
		return sig.sign.Serialize()
	}
}

func (sig *BlsSign) Deserialize(buf []byte) error {
	if (tmpDebugMode == 1)	{
		return sig.sign.Deserialize(buf)
	} else {
		return sig.sign.Deserialize(buf)
	}
}

func (sig *BlsSign) VerifyHash(pub *BlsPublicKey, hash []byte) bool {
	if (tmpDebugMode == 1)	{
		return sig.sign.VerifyHash(&pub.publicKey, hash)
	} else {
		return sig.sign.VerifyHash(&pub.publicKey, hash)
	}
}

// PublicKeySizeInBytes ..
const (
	PublicKeySizeInBytes    = 48
	BLSSignatureSizeInBytes = 96
)

// PrivateKeyWrapper combines the bls private key and the corresponding public key
type PrivateKeyWrapper struct {
	Pri *BlsSecretKey
	Pub *PublicKeyWrapper
}

// PublicKeyWrapper defines the bls public key in both serialized and
// deserialized form.
type PublicKeyWrapper struct {
	Bytes  SerializedPublicKey
	Object *BlsPublicKey
}

// WrapperFromPrivateKey makes a PrivateKeyWrapper from bls secret key
func WrapperFromPrivateKey(pri *BlsSecretKey) PrivateKeyWrapper {
	pub := pri.GetPublicKey()
	pubKeyWrapper := &BlsPublicKey{}
	pubKeyWrapper.DeserializeHexStr(pub.SerializeToHexStr())
	pubBytes := FromLibBLSPublicKeyUnsafe(pubKeyWrapper)
	return PrivateKeyWrapper{
		Pri: pri,
		Pub: &PublicKeyWrapper{
			Bytes:  *pubBytes,
			Object: pubKeyWrapper,
		},
	}
}

// SerializedPublicKey defines the serialized bls public key
type SerializedPublicKey [PublicKeySizeInBytes]byte

// SerializedSignature defines the bls signature
type SerializedSignature [BLSSignatureSizeInBytes]byte

// Big ..
func (pk SerializedPublicKey) Big() *big.Int {
	return new(big.Int).SetBytes(pk[:])
}

// IsEmpty returns whether the bls public key is empty 0 bytes
func (pk SerializedPublicKey) IsEmpty() bool {
	return bytes.Equal(pk[:], emptyBLSPubKey[:])
}

// Hex returns the hex string of bls public key
func (pk SerializedPublicKey) Hex() string {
	return hex.EncodeToString(pk[:])
}

// MarshalText so that we can use this as JSON printable when used as
// key in a map
func (pk SerializedPublicKey) MarshalText() (text []byte, err error) {
	text = make([]byte, BLSSignatureSizeInBytes)
	hex.Encode(text, pk[:])
	return text, nil
}

// FromLibBLSPublicKeyUnsafe could give back nil, use only in cases when
// have invariant that return value won't be nil
func FromLibBLSPublicKeyUnsafe(key *BlsPublicKey) *SerializedPublicKey {
	result := &SerializedPublicKey{}
	if err := result.FromLibBLSPublicKey(key); err != nil {
		return nil
	}
	return result
}

// FromLibBLSPublicKey replaces the key contents with the given key,
func (pk *SerializedPublicKey) FromLibBLSPublicKey(key *BlsPublicKey) error {
	bytes := key.Serialize()
	if len(bytes) != len(pk) {
		return errors.Errorf(
			"key size (BLS) size mismatch, expected %d have %d", len(pk), len(bytes),
		)
	}
	copy(pk[:], bytes)
	return nil
}

// SeparateSigAndMask parse the commig signature data into signature and bitmap.
func SeparateSigAndMask(commitSigs []byte) ([]byte, []byte, error) {
	if len(commitSigs) < BLSSignatureSizeInBytes {
		return nil, nil, errors.Errorf("no mask data found in commit sigs: %x", commitSigs)
	}
	//#### Read payload data from committed msg
	aggSig := make([]byte, BLSSignatureSizeInBytes)
	bitmap := make([]byte, len(commitSigs)-BLSSignatureSizeInBytes)
	offset := 0
	copy(aggSig[:], commitSigs[offset:offset+BLSSignatureSizeInBytes])
	offset += BLSSignatureSizeInBytes
	copy(bitmap[:], commitSigs[offset:])
	//#### END Read payload data from committed msg
	return aggSig, bitmap, nil
}

func Init() {
	bls.Init(bls.BLS12_381)
}