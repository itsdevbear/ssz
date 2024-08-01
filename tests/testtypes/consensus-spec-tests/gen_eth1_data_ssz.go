// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package consensus_spec_tests

import "github.com/karalabe/ssz"

// SizeSSZ returns the total size of the static ssz object.
func (obj *Eth1Data) SizeSSZ() uint32 {
	return 32 + 8 + 32
}

// DefineSSZ defines how an object is encoded/decoded.
func (obj *Eth1Data) DefineSSZ(codec ssz.CodecI) {
	ssz.DefineStaticBytes(codec, &obj.DepositRoot) // Field  (0) -  DepositRoot - 32 bytes
	ssz.DefineUint64(codec, &obj.DepositCount)     // Field  (1) - DepositCount -  8 bytes
	ssz.DefineStaticBytes(codec, &obj.BlockHash)   // Field  (2) -    BlockHash - 32 bytes
}
