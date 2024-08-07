// ssz: Go Simple Serialize (SSZ) codec library
// Copyright 2024 ssz Authors
// SPDX-License-Identifier: BSD-3-Clause

package ssz

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	bitops "math/bits"
	"runtime"
	"unsafe"

	"github.com/holiman/uint256"
	"github.com/prysmaticlabs/go-bitfield"
	"golang.org/x/sync/errgroup"
)

func init() {
	var buf [64]byte
	for i := 0; i < len(hasherZeroCache)-1; i++ {
		copy(buf[:32], hasherZeroCache[i][:])
		copy(buf[32:], hasherZeroCache[i][:])

		hasherZeroCache[i+1] = sha256.Sum256(buf[:])
	}
}

// TreeNode represents a node in the Merkle tree
type TreeNode struct {
	Value   [32]byte
	Left    *TreeNode
	Right   *TreeNode
}

// Treerer2 is an SSZ Merkle Hash Root computer.
type Treerer2 struct {
	Hasher
	tree  []*TreeNode
}

// TreeBool hashes a boolean.
func TreeBool[T ~bool](h *Treerer2, v T) {
	if !v {
		h.insertChunk(hasherBoolFalse, 0)
	} else {
		h.insertChunk(hasherBoolTrue, 0)
	}
}

// TreeUint8 hashes a uint8.
func TreeUint8[T ~uint8](h *Treerer2, n T) {
	var buffer [32]byte
	buffer[0] = uint8(n)
	h.insertChunk(buffer, 0)
}

// TreeUint16 hashes a uint16.
func TreeUint16[T ~uint16](h *Treerer2, n T) {
	var buffer [32]byte
	binary.LittleEndian.PutUint16(buffer[:], uint16(n))
	h.insertChunk(buffer, 0)
}

// TreeUint32 hashes a uint32.
func TreeUint32[T ~uint32](h *Treerer2, n T) {
	var buffer [32]byte
	binary.LittleEndian.PutUint32(buffer[:], uint32(n))
	h.insertChunk(buffer, 0)
}

// TreeUint64 hashes a uint64.
func TreeUint64[T ~uint64](h *Treerer2, n T) {
	var buffer [32]byte
	binary.LittleEndian.PutUint64(buffer[:], uint64(n))
	h.insertChunk(buffer, 0)
}

// TreeUint256 hashes a uint256.
//
// Note, a nil pointer is hashed as zero.
func TreeUint256(h *Treerer2, n *uint256.Int) {
	var buffer [32]byte
	if n != nil {
		n.MarshalSSZInto(buffer[:])
	}
	h.insertChunk(buffer, 0)
}

// TreeUint256BigInt hashes a big.Int as uint256.
//
// Note, a nil pointer is hashed as zero.
func TreeUint256BigInt(h *Treerer2, n *big.Int) {
	var buffer [32]byte
	if n != nil {
		var bufint uint256.Int // No pointer, alloc free
		bufint.SetFromBig(n)
		bufint.MarshalSSZInto(buffer[:])
	}
	h.insertChunk(buffer, 0)
}

// TreeStaticBytes hashes a static binary blob.
//
// The blob is passed by pointer to avoid high stack copy costs and a potential
// escape to the heap.
func TreeStaticBytes[T commonBytesLengths](h *Treerer2, blob *T) {
	// The code below should have used `blob[:]`, alas Go's generics compiler
	// is missing that (i.e. a bug): https://github.com/golang/go/issues/51740
	h.hashBytes(unsafe.Slice(&(*blob)[0], len(*blob)))
}

// TreeCheckedStaticBytes hashes a static binary blob.
func TreeCheckedStaticBytes(h *Treerer2, blob []byte) {
	h.hashBytes(blob)
}

// TreeDynamicBytes hashes a dynamic binary blob.
func TreeDynamicBytes(h *Treerer2, blob []byte, maxSize uint64) {
	h.descendMixinLayer()
	h.insertBlobChunks(blob)
	h.ascendMixinLayer(uint64(len(blob)), (maxSize+31)/32)
}

// TreeStaticObject hashes a static ssz object.
func TreeStaticObject(h *Treerer2, obj StaticObject) {
	h.descendLayer()
	obj.DefineSSZ(h.codec)
	h.ascendLayer(0)
}

// TreeDynamicObject hashes a dynamic ssz object.
func TreeDynamicObject(h *Treerer2, obj DynamicObject) {
	h.descendLayer()
	obj.DefineSSZ(h.codec)
	h.ascendLayer(0)
}

// TreeArrayOfBits hashes a static array of (packed) bits.
func TreeArrayOfBits[T commonBitsLengths](h *Treerer2, bits *T) {
	// The code below should have used `*bits[:]`, alas Go's generics compiler
	// is missing that (i.e. a bug): https://github.com/golang/go/issues/51740
	h.hashBytes(unsafe.Slice(&(*bits)[0], len(*bits)))
}

// TreeSliceOfBits hashes a dynamic slice of (packed) bits.
func TreeSliceOfBits(h *Treerer2, bits bitfield.Bitlist, maxBits uint64) {
	// Parse the bit-list into a hashable representation
	var (
		msb  = uint8(bitops.Len8(bits[len(bits)-1])) - 1
		size = uint64((len(bits)-1)<<3 + int(msb))
	)
	h.bitbuf = append(h.bitbuf[:0], bits...)
	h.bitbuf[len(h.bitbuf)-1] &^= uint8(1 << msb)

	newLen := len(h.bitbuf)
	for i := len(h.bitbuf) - 1; i >= 0; i-- {
		if h.bitbuf[i] != 0x00 {
			break
		}
		newLen = i
	}
	h.bitbuf = h.bitbuf[:newLen]

	// Merkleize the content with mixed in length
	h.descendMixinLayer()
	if len(h.bitbuf) == 0 && size > 0 {
		h.insertChunk([32]byte{}, 0)
	} else {
		h.insertBlobChunks(h.bitbuf)
	}
	h.ascendMixinLayer(size, (maxBits+255)/256)
}

// TreeArrayOfUint64s hashes a static array of uint64s.
//
// The reason the ns is passed by pointer and not by value is to prevent it from
// escaping to the heap (and incurring an allocation) when passing it to the
// hasher.
func TreeArrayOfUint64s[T commonUint64sLengths](h *Treerer2, ns *T) {
	// The code below should have used `*blob[:]`, alas Go's generics compiler
	// is missing that (i.e. a bug): https://github.com/golang/go/issues/51740
	nums := unsafe.Slice(&(*ns)[0], len(*ns))
	h.descendLayer()

	var buffer [32]byte
	for len(nums) > 4 {
		binary.LittleEndian.PutUint64(buffer[:], nums[0])
		binary.LittleEndian.PutUint64(buffer[8:], nums[1])
		binary.LittleEndian.PutUint64(buffer[16:], nums[2])
		binary.LittleEndian.PutUint64(buffer[24:], nums[3])

		h.insertChunk(buffer, 0)
		nums = nums[4:]
	}
	if len(nums) > 0 {
		buffer = [32]byte{}
		for i := 0; i < len(nums); i++ {
			binary.LittleEndian.PutUint64(buffer[i<<3:], nums[i])
		}
		h.insertChunk(buffer, 0)
	}
	h.ascendLayer(0)
}

// TreeSliceOfUint64s hashes a dynamic slice of uint64s.
func TreeSliceOfUint64s[T ~uint64](h *Treerer2, ns []T, maxItems uint64) {
	h.descendMixinLayer()
	nums := ns

	var buffer [32]byte
	for len(nums) > 4 {
		binary.LittleEndian.PutUint64(buffer[:], uint64(nums[0]))
		binary.LittleEndian.PutUint64(buffer[8:], uint64(nums[1]))
		binary.LittleEndian.PutUint64(buffer[16:], uint64(nums[2]))
		binary.LittleEndian.PutUint64(buffer[24:], uint64(nums[3]))

		h.insertChunk(buffer, 0)
		nums = nums[4:]
	}
	if len(nums) > 0 {
		buffer = [32]byte{}
		for i := 0; i < len(nums); i++ {
			binary.LittleEndian.PutUint64(buffer[i<<3:], uint64(nums[i]))
		}
		h.insertChunk(buffer, 0)
	}
	h.ascendMixinLayer(uint64(len(ns)), (maxItems*8+31)/32)
}

// TreeArrayOfStaticBytes hashes a static array of static binary blobs.
//
// The reason the blobs is passed by pointer and not by value is to prevent it
// from escaping to the heap (and incurring an allocation) when passing it to
// the output stream.
func TreeArrayOfStaticBytes[T commonBytesArrayLengths[U], U commonBytesLengths](h *Treerer2, blobs *T) {
	// The code below should have used `(*blobs)[:]`, alas Go's generics compiler
	// is missing that (i.e. a bug): https://github.com/golang/go/issues/51740
	TreeUnsafeArrayOfStaticBytes(h, unsafe.Slice(&(*blobs)[0], len(*blobs)))
}

// TreeUnsafeArrayOfStaticBytes hashes a static array of static binary blobs.
func TreeUnsafeArrayOfStaticBytes[T commonBytesLengths](h *Treerer2, blobs []T) {
	h.descendLayer()
	for i := 0; i < len(blobs); i++ {
		// The code below should have used `blobs[i][:]`, alas Go's generics compiler
		// is missing that (i.e. a bug): https://github.com/golang/go/issues/51740
		h.hashBytes(unsafe.Slice(&blobs[i][0], len(blobs[i])))
	}
	h.ascendLayer(0)
}

// TreeCheckedArrayOfStaticBytes hashes a static array of static binary blobs.
func TreeCheckedArrayOfStaticBytes[T commonBytesLengths](h *Treerer2, blobs []T) {
	h.descendLayer()
	for i := 0; i < len(blobs); i++ {
		// The code below should have used `blobs[i][:]`, alas Go's generics compiler
		// is missing that (i.e. a bug): https://github.com/golang/go/issues/51740
		h.hashBytes(unsafe.Slice(&blobs[i][0], len(blobs[i])))
	}
	h.ascendLayer(0)
}

// TreeSliceOfStaticBytes hashes a dynamic slice of static binary blobs.
func TreeSliceOfStaticBytes[T commonBytesLengths](h *Treerer2, blobs []T, maxItems uint64) {
	h.descendMixinLayer()
	for i := 0; i < len(blobs); i++ {
		// The code below should have used `blobs[i][:]`, alas Go's generics compiler
		// is missing that (i.e. a bug): https://github.com/golang/go/issues/51740
		h.hashBytes(unsafe.Slice(&blobs[i][0], len(blobs[i])))
	}
	h.ascendMixinLayer(uint64(len(blobs)), maxItems)
}

// TreeSliceOfDynamicBytes hashes a dynamic slice of dynamic binary blobs.
func TreeSliceOfDynamicBytes(h *Treerer2, blobs [][]byte, maxItems uint64, maxSize uint64) {
	h.descendMixinLayer()
	for _, blob := range blobs {
		h.descendMixinLayer()
		h.insertBlobChunks(blob)
		h.ascendMixinLayer(uint64(len(blob)), (maxSize+31)/32)
	}
	h.ascendMixinLayer(uint64(len(blobs)), maxItems)
}

// TreeSliceOfStaticObjects hashes a dynamic slice of static ssz objects.
func TreeSliceOfStaticObjects[T StaticObject](h *Treerer2, objects []T, maxItems uint64) {
	h.descendMixinLayer()
	defer h.ascendMixinLayer(uint64(len(objects)), maxItems)

	// If threading is disabled, or hashing nothing, do it sequentially
	if !h.threads || len(objects) == 0 || len(objects)*int(Size(objects[0])) < concurrencyThreshold {
		for _, obj := range objects {
			h.descendLayer()
			obj.DefineSSZ(h.codec)
			h.ascendLayer(0)
		}
		return
	}
	// Split the slice into equal chunks and hash the objects concurrently. The
	// splits will in theory be objects // threads. In practice, we need powers
	// of 2, otherwise child hashers wouldn't be able to collapse their tasks
	// into a single sub-root. Going for the biggest power of two that can be
	// served by exactly N threads is a problem, because we can end up with N/2-1
	// threads idling at worse. To avoid starvation, we're splitting across a
	// higher thead count than cores.
	var workers errgroup.Group
	workers.SetLimit(runtime.NumCPU())

	var (
		splits  = min(4*runtime.NumCPU(), len(objects))
		subtask = max(1<<bitops.Len(uint(len(objects)/splits)), 1)

		resultChunks = make([][32]byte, (len(objects)+subtask-1)/subtask)
		resultDepths = make([]int, (len(objects)+subtask-1)/subtask)
	)
	for i := 0; i < len(resultChunks); i++ {
		worker := i // Take care, closure

		workers.Go(func() error {
			codec := hasherPool.Get().(*Codec)
			defer hasherPool.Put(codec)
			defer codec.has.Reset()
			codec.has.threads = true

			for i := worker * subtask; i < (worker+1)*subtask && i < len(objects); i++ {
				codec.has.descendLayer()
				objects[i].DefineSSZ(codec)
				codec.has.ascendLayer(0)
			}
			codec.has.balanceLayer()

			resultChunks[worker] = codec.has.chunks[0]
			resultDepths[worker] = codec.has.groups[0].depth
			return nil
		})
	}
	// Wait for all the hashers to finish and aggregate the results
	workers.Wait()
	for i := 0; i < len(resultChunks); i++ {
		h.insertChunk(resultChunks[i], resultDepths[i])
	}
}

// TreeSliceOfDynamicObjects hashes a dynamic slice of dynamic ssz objects.
func TreeSliceOfDynamicObjects[T DynamicObject](h *Hasher, objects []T, maxItems uint64) {
	h.descendMixinLayer()
	for _, obj := range objects {
		h.descendLayer()
		obj.DefineSSZ(h.codec)
		h.ascendLayer(0)
	}
	h.ascendMixinLayer(uint64(len(objects)), maxItems)
}

func (h *Treerer2) createTree() []*TreeNode {
        length := len(h.chunks)
        if length == 0 {
                return nil
        }
        leaves := make([]*TreeNode, length)
        for i, c := range h.chunks {
                leaves[i] = &TreeNode{Left:nil, Right:nil, Value:c,}
        }
        bottomLength := ceilPowerOfTwo(length)
        h.tree = make([]*TreeNode, 2*bottomLength)
        copy(h.tree[bottomLength:bottomLength+length], leaves)

        for i := bottomLength - 1; i > 0 ; i-- {
                left := h.tree[2*i]
                right := h.tree[2*i+1]
                if left == nil && right == nil {
                        continue
                }
                if right == nil {
                        right = &TreeNode{Value: hasherZeroCache[i],}
                        h.tree[2*i+1] = right
                }
                h.tree[i] = &TreeNode{
                        Left: left,
                        Right: right,
                        Value: sha256.Sum256(append(left.Value[:], right.Value[:]...)),
                }
        }
        return h.tree
}

func ceilPowerOfTwo(u int) int {
        if u == 0 {
                return 1
        }
        u--
        u |= u >> 1
        u |= u >> 2
        u |= u >> 4
        u |= u >> 8
        u |= u >> 16
        u |= u >> 32
        u++
        return u
}

