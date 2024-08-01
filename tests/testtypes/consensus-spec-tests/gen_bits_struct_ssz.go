// Code generated by github.com/karalabe/ssz. DO NOT EDIT.

package consensus_spec_tests

import "github.com/karalabe/ssz"

// SizeSSZ returns either the static size of the object if fixed == true, or
// the total size otherwise.
func (obj *BitsStruct) SizeSSZ(fixed bool) uint32 {
	var size = uint32(4 + 1 + 1 + 4 + 1)
	if fixed {
		return size
	}
	size += ssz.SizeSliceOfBits(obj.A)
	size += ssz.SizeSliceOfBits(obj.D)

	return size
}

// DefineSSZ defines how an object is encoded/decoded.
func (obj *BitsStruct) DefineSSZ(codec ssz.CodecI) {
	// Define the static data (fields and dynamic offsets)
	ssz.DefineSliceOfBitsOffset(codec, &obj.A, 5) // Offset (0) - A - 4 bytes
	ssz.DefineArrayOfBits(codec, &obj.B, 2)       // Field  (1) - B - 1 bytes
	ssz.DefineArrayOfBits(codec, &obj.C, 1)       // Field  (2) - C - 1 bytes
	ssz.DefineSliceOfBitsOffset(codec, &obj.D, 6) // Offset (3) - D - 4 bytes
	ssz.DefineArrayOfBits(codec, &obj.E, 8)       // Field  (4) - E - 1 bytes

	// Define the dynamic data (fields)
	ssz.DefineSliceOfBitsContent(codec, &obj.A, 5) // Field  (0) - A - ? bytes
	ssz.DefineSliceOfBitsContent(codec, &obj.D, 6) // Field  (3) - D - ? bytes
}
