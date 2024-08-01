// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package consensus_spec_tests

import "github.com/karalabe/ssz"

// Cached static size computed on package init.
var staticSizeCacheSignedBLSToExecutionChange = (*BLSToExecutionChange)(nil).SizeSSZ() + 96

// SizeSSZ returns the total size of the static ssz object.
func (obj *SignedBLSToExecutionChange) SizeSSZ() uint32 {
	return staticSizeCacheSignedBLSToExecutionChange
}

// DefineSSZ defines how an object is encoded/decoded.
func (obj *SignedBLSToExecutionChange) DefineSSZ(codec *ssz.Codec) {
	ssz.DefineStaticObject(codec, &obj.Message)  // Field  (0) -   Message -  ? bytes (BLSToExecutionChange)
	ssz.DefineStaticBytes(codec, &obj.Signature) // Field  (1) - Signature - 96 bytes
}
