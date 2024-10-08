// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package consensus_spec_tests

import "github.com/karalabe/ssz"

// SizeSSZ returns the total size of the static ssz object.
func (obj *FixedTestStructMonolith) SizeSSZ(sizer *ssz.Sizer) (size uint32) {
	if sizer.Fork() >= ssz.ForkUnknown {
		size += 1 + 8 + 4
	}
	return size
}

// DefineSSZ defines how an object is encoded/decoded.
func (obj *FixedTestStructMonolith) DefineSSZ(codec *ssz.Codec) {
	ssz.DefineUint8PointerOnFork(codec, &obj.A, ssz.ForkFilter{Added: ssz.ForkUnknown})  // Field  (0) - A - 1 bytes
	ssz.DefineUint64PointerOnFork(codec, &obj.B, ssz.ForkFilter{Added: ssz.ForkUnknown}) // Field  (1) - B - 8 bytes
	ssz.DefineUint32PointerOnFork(codec, &obj.C, ssz.ForkFilter{Added: ssz.ForkUnknown}) // Field  (2) - C - 4 bytes
}
