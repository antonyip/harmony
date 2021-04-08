package bls_interface

// "github.com/harmony-one/harmony/crypto/bls_interface"
import (
	"bytes"
	"encoding/hex"
	"math/big"

	"github.com/harmony-one/bls/ffi/go/bls"
	blst "github.com/supranational/blst/bindings/go"
	"github.com/pkg/errors"
)

var (
	emptyBLSPubKey = SerializedPublicKey{}
)

type BlsSecretKey struct {
	SecretKey bls.SecretKey
}

type BlsPublicKey struct {
	PublicKey bls.PublicKey
}

type BlsSign struct {
	Sign bls.Sign
}

func (s *BlsSign) SerializeToHexStr() string {
	return s.Sign.SerializeToHexStr()
}

func (s* BlsSign) DeserializeHexStr(str string) error {
	return s.Sign.DeserializeHexStr(str)
}

func (s *BlsPublicKey) SerializeToHexStr() string {
	if (&(s.PublicKey) == nil) {
		s.PublicKey = bls.PublicKey{}
	}
	return s.PublicKey.SerializeToHexStr()
}

func (s* BlsPublicKey) DeserializeHexStr(str string) error {
	return s.PublicKey.DeserializeHexStr(str)
}

func (s *BlsSecretKey) SerializeToHexStr() string {
	return s.SecretKey.SerializeToHexStr()
}

func (s* BlsSecretKey) DeserializeHexStr(str string) error {
	return s.SecretKey.DeserializeHexStr(str)
}

func (s* BlsSign) Add(rhs *BlsSign) {
	s.Sign.Add(&rhs.Sign)
}

func (s* BlsPublicKey) Add(rhs *BlsPublicKey) {
	s.PublicKey.Add(&rhs.PublicKey)
}

func (s* BlsPublicKey) Sub(rhs *BlsPublicKey) {
	s.PublicKey.Sub(&rhs.PublicKey)
}

func (sec *BlsSecretKey) SignHash(hash []byte) (sig *BlsSign){
	returnValue := &BlsSign{}
	Siggy := sec.SecretKey.SignHash(hash)
	strVal := Siggy.SerializeToHexStr()
	returnValue.Sign.DeserializeHexStr(strVal)
	return returnValue
}

func (sig *BlsSign) Serialize() []byte {
	return sig.Sign.Serialize()
}

func (sig *BlsSign) Deserialize(buf []byte) error {
	return sig.Sign.Deserialize(buf)
}

func (sig *BlsSign) VerifyHash(pub *BlsPublicKey, hash []byte) bool {
	return sig.Sign.VerifyHash(&pub.PublicKey, hash)
}

func (pub *BlsPublicKey) GetAddress() [20]byte {
	return pub.PublicKey.GetAddress()
}

func (pub *BlsPublicKey) IsEqual(rhs *BlsPublicKey) bool {
	return pub.PublicKey.IsEqual(&rhs.PublicKey)
}

func (sec *BlsSecretKey) SetByCSPRNG() {
	sec.SecretKey.SetByCSPRNG()
}

func (sec *BlsSecretKey) GetPublicKey() (pub *BlsPublicKey) {
	returnValue := &BlsPublicKey{}
	returnValue.DeserializeHexStr(sec.GetPublicKey().SerializeToHexStr())
	return returnValue
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
	pub := pri.SecretKey.GetPublicKey()
	pubKeyWrapper := &BlsPublicKey{}
	pubKeyWrapper.PublicKey.DeserializeHexStr(pub.SerializeToHexStr())
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
	bytes := key.PublicKey.Serialize()
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
	blst.SetMaxProcs(1)
}