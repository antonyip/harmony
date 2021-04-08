package chain

import (
	"errors"

	"github.com/harmony-one/harmony/crypto/bls_interface"
	"github.com/harmony-one/harmony/internal/utils"
)

// ReadSignatureBitmapByPublicKeys read the payload of signature and bitmap based on public keys
func ReadSignatureBitmapByPublicKeys(recvPayload []byte, publicKeys []bls_interface.PublicKeyWrapper) (*bls_interface.BlsSign, *bls_interface.Mask, error) {
	sig, bitmap, err := ParseCommitSigAndBitmap(recvPayload)
	if err != nil {
		return nil, nil, err
	}
	return DecodeSigBitmap(sig, bitmap, publicKeys)
}

// ParseCommitSigAndBitmap parse the commitSigAndBitmap to signature + bitmap
func ParseCommitSigAndBitmap(payload []byte) (bls_interface.SerializedSignature, []byte, error) {
	if len(payload) < bls_interface.BLSSignatureSizeInBytes {
		return bls_interface.SerializedSignature{}, nil, errors.New("payload not have enough length")
	}
	var (
		sig    bls_interface.SerializedSignature
		bitmap = make([]byte, len(payload)-bls_interface.BLSSignatureSizeInBytes)
	)
	copy(sig[:], payload[:bls_interface.BLSSignatureSizeInBytes])
	copy(bitmap, payload[bls_interface.BLSSignatureSizeInBytes:])

	return sig, bitmap, nil
}

// DecodeSigBitmap decode and parse the signature, bitmap with the given public keys
func DecodeSigBitmap(sigBytes bls_interface.SerializedSignature, bitmap []byte, pubKeys []bls_interface.PublicKeyWrapper) (*bls_interface.BlsSign, *bls_interface.Mask, error) {
	aggSig := bls_interface.BlsSign{}
	err := aggSig.Deserialize(sigBytes[:])
	if err != nil {
		return nil, nil, errors.New("unable to deserialize multi-signature from payload")
	}
	mask, err := bls_interface.NewMask(pubKeys, nil)
	if err != nil {
		utils.Logger().Warn().Err(err).Msg("onNewView unable to setup mask for prepared message")
		return nil, nil, errors.New("unable to setup mask from payload")
	}
	if err := mask.SetMask(bitmap); err != nil {
		utils.Logger().Warn().Err(err).Msg("mask.SetMask failed")
	}
	return &aggSig, mask, nil
}
