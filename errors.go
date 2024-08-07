// ssz: Go Simple Serialize (SSZ) codec library
// Copyright 2024 ssz Authors
// SPDX-License-Identifier: BSD-3-Clause

package ssz

import "errors"

// ErrBufferTooSmall is returned from encoding if the provided output byte buffer
// is too small to hold the encoding of the object.
var ErrBufferTooSmall = errors.New("ssz: output buffer too small")

// ErrFirstOffsetMismatch is returned when parsing dynamic types and the first
// offset (which is supposed to signal the start of the dynamic area) does not
// match with the computed fixed area size.
var ErrFirstOffsetMismatch = errors.New("ssz: first offset mismatch")

// ErrBadOffsetProgression is returned when an offset is parsed, and is smaller
// than a previously seen offset (meaning negative dynamic data size).
var ErrBadOffsetProgression = errors.New("ssz: offset smaller than previous")

// ErrOffsetBeyondCapacity is returned when an offset is parsed, and is larger
// than the total capacity allowed by the decoder (i.e. message size)
var ErrOffsetBeyondCapacity = errors.New("ssz: offset beyond capacity")

// ErrMaxLengthExceeded is returned when the size calculated for a dynamic type
// is larger than permitted.
var ErrMaxLengthExceeded = errors.New("ssz: maximum item size exceeded")

// ErrMaxItemsExceeded is returned when the number of items in a dynamic list
// type is later than permitted.
var ErrMaxItemsExceeded = errors.New("ssz: maximum item count exceeded")

// ErrShortCounterOffset is returned if a counter offset it attempted to be read
// but there are fewer bytes available on the stream.
var ErrShortCounterOffset = errors.New("ssz: insufficient data for 4-byte counter offset")

// ErrZeroCounterOffset is returned when a list of offsets are consumed and the
// first offset is zero, which means the list should not have existed.
var ErrZeroCounterOffset = errors.New("ssz: counter offset zero")

// ErrBadCounterOffset is returned when a list of offsets are consumed and the
// first offset is not a multiple of 4-bytes.
var ErrBadCounterOffset = errors.New("ssz: counter offset not multiple of 4-bytes")

// ErrDynamicStaticsIndivisible is returned when a list of static objects is to
// be decoded, but the list's total length is not divisible by the item size.
var ErrDynamicStaticsIndivisible = errors.New("ssz: list of fixed objects not divisible")

// ErrObjectSlotSizeMismatch is returned from decoding if an object's slot in the
// ssz stream contains more data than the object cares to consume.
var ErrObjectSlotSizeMismatch = errors.New("ssz: object didn't consume all designated data")

// ErrInvalidBoolean is returned from decoding if a boolean slot contains some
// other byte than 0x00 or 0x01.
var ErrInvalidBoolean = errors.New("ssz: invalid boolean")

// ErrJunkInBitvector is returned from decoding if the high (unused) bits of a
// bitvector contains junk, instead of being all 0.
var ErrJunkInBitvector = errors.New("ssz: junk in bitvector unused bits")

// ErrJunkInBitlist is returned from decoding if the high (unused) bits of a
// bitlist contains junk, instead of being all 0.
var ErrJunkInBitlist = errors.New("ssz: junk in bitlist unused bits")
