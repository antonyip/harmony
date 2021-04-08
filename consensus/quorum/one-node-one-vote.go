package quorum

import (
	"encoding/json"
	"math/big"

	"github.com/harmony-one/harmony/crypto/bls_interface"

	"github.com/ethereum/go-ethereum/common"
	"github.com/harmony-one/harmony/consensus/votepower"

	"github.com/harmony-one/harmony/internal/utils"
	"github.com/harmony-one/harmony/numeric"
	"github.com/harmony-one/harmony/shard"
)

type uniformVoteWeight struct {
	DependencyInjectionWriter
	DependencyInjectionReader
	SignatureReader
}

// Policy ..
func (v *uniformVoteWeight) Policy() Policy {
	return SuperMajorityVote
}

// AddNewVote ..
func (v *uniformVoteWeight) AddNewVote(
	p Phase, pubKeys []*bls_interface.PublicKeyWrapper,
	sig *bls_interface.BlsSign, headerHash common.Hash,
	height, viewID uint64) (*votepower.Ballot, error) {
	pubKeysBytes := make([]bls_interface.SerializedPublicKey, len(pubKeys))
	for i, pubKey := range pubKeys {
		pubKeysBytes[i] = pubKey.Bytes
	}
	return v.submitVote(p, pubKeysBytes, sig, headerHash, height, viewID)
}

// IsQuorumAchieved ..
func (v *uniformVoteWeight) IsQuorumAchieved(p Phase) bool {
	r := v.SignersCount(p) >= v.TwoThirdsSignersCount()
	utils.Logger().Info().Str("phase", p.String()).
		Int64("signers-count", v.SignersCount(p)).
		Int64("threshold", v.TwoThirdsSignersCount()).
		Int64("participants", v.ParticipantsCount()).
		Msg("Quorum details")
	return r
}

// IsQuorumAchivedByMask ..
func (v *uniformVoteWeight) IsQuorumAchievedByMask(mask *bls_interface.Mask) bool {
	if mask == nil {
		return false
	}
	threshold := v.TwoThirdsSignersCount()
	currentTotalPower := utils.CountOneBits(mask.Bitmap)
	if currentTotalPower < threshold {
		const msg = "[IsQuorumAchievedByMask] Not enough voting power: need %+v, have %+v"
		utils.Logger().Warn().Msgf(msg, threshold, currentTotalPower)
		return false
	}
	const msg = "[IsQuorumAchievedByMask] have enough voting power: need %+v, have %+v"
	utils.Logger().Debug().
		Msgf(msg, threshold, currentTotalPower)
	return true
}

// QuorumThreshold ..
func (v *uniformVoteWeight) QuorumThreshold() numeric.Dec {
	return numeric.NewDec(v.TwoThirdsSignersCount())
}

// IsAllSigsCollected ..
func (v *uniformVoteWeight) IsAllSigsCollected() bool {
	return v.SignersCount(Commit) == v.ParticipantsCount()
}

func (v *uniformVoteWeight) SetVoters(
	subCommittee *shard.Committee, epoch *big.Int,
) (*TallyResult, error) {
	// NO-OP do not add anything here
	return nil, nil
}

func (v *uniformVoteWeight) String() string {
	s, _ := json.Marshal(v)
	return string(s)
}

func (v *uniformVoteWeight) MarshalJSON() ([]byte, error) {
	type t struct {
		Policy       string   `json:"policy"`
		Count        int      `json:"count"`
		Participants []string `json:"committee-members"`
	}
	keysDump := v.Participants()
	keys := make([]string, len(keysDump))
	for i := range keysDump {
		keys[i] = keysDump[i].Bytes.Hex()
	}

	return json.Marshal(t{v.Policy().String(), len(keys), keys})
}

func (v *uniformVoteWeight) AmIMemberOfCommitee() bool {
	pubKeyFunc := v.MyPublicKey()
	if pubKeyFunc == nil {
		return false
	}
	identity, _ := pubKeyFunc()
	everyone := v.Participants()
	for _, key := range identity {
		for i := range everyone {
			if key.Object.IsEqual(everyone[i].Object) {
				return true
			}
		}
	}
	return false
}

func (v *uniformVoteWeight) ResetPrepareAndCommitVotes() {
	v.reset([]Phase{Prepare, Commit})
}

func (v *uniformVoteWeight) ResetViewChangeVotes() {
	v.reset([]Phase{ViewChange})
}
