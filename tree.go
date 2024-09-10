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
	"github.com/prysmaticlabs/gohashtree"
	"golang.org/x/sync/errgroup"
)

// treererBatch is the number of chunks to batch up before calling the treerer.
const treererBatch = 8 // *MUST* be power of 2

// Some helpers to avoid occasional allocations
var (
	treererBoolFalse = [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	treererBoolTrue  = [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	// treererZeroCache is a pre-computed table of all-zero sub-trie treeing
	treererZeroCache [65][32]byte
)

func init() {
	var buf [64]byte
	for i := 0; i < len(treererZeroCache)-1; i++ {
		copy(buf[:32], treererZeroCache[i][:])
		copy(buf[32:], treererZeroCache[i][:])

		treererZeroCache[i+1] = sha256.Sum256(buf[:])
	}
}

type Node struct {
	Hash   [32]byte
	Left   *Node
	Right  *Node
	Parent *Node
}

// Treerer is an SSZ Merkle Hash Root computer.
type Treerer struct {
	threads bool // Whether threaded treeing is allowed or not

	chunks [][32]byte   // Scratch space for in-progress treeing chunks
	groups []groupStats // Treeing progress tracking for the chunk groups
	layer  int          // Layer depth being treerer now

	codec  *Codec // Self-referencing to pass DefineSSZ calls through (API trick)
	bitbuf []byte // Bitlist conversion buffer

	// ... (existing fields)
	nodes []*Node
	root  *Node
}

// TreeBool trees a boolean.
func TreeBool[T ~bool](h *Treerer, v T) {
	if !v {
		h.insertChunk(treererBoolFalse, 0)
	} else {
		h.insertChunk(treererBoolTrue, 0)
	}
}

// TreeUint8 trees a uint8.
func TreeUint8[T ~uint8](h *Treerer, n T) {
	var buffer [32]byte
	buffer[0] = uint8(n)
	h.insertChunk(buffer, 0)
}

// TreeUint16 trees a uint16.
func TreeUint16[T ~uint16](h *Treerer, n T) {
	var buffer [32]byte
	binary.LittleEndian.PutUint16(buffer[:], uint16(n))
	h.insertChunk(buffer, 0)
}

// TreeUint32 trees a uint32.
func TreeUint32[T ~uint32](h *Treerer, n T) {
	var buffer [32]byte
	binary.LittleEndian.PutUint32(buffer[:], uint32(n))
	h.insertChunk(buffer, 0)
}

// TreeUint64 trees a uint64.
func TreeUint64[T ~uint64](h *Treerer, n T) {
	var buffer [32]byte
	binary.LittleEndian.PutUint64(buffer[:], uint64(n))
	h.insertChunk(buffer, 0)
}

// TreeUint256 trees a uint256.
//
// Note, a nil pointer is treed as zero.
func TreeUint256(h *Treerer, n *uint256.Int) {
	var buffer [32]byte
	if n != nil {
		n.MarshalSSZInto(buffer[:])
	}
	h.insertChunk(buffer, 0)
}

// TreeUint256BigInt trees a big.Int as uint256.
//
// Note, a nil pointer is treed as zero.
func TreeUint256BigInt(h *Treerer, n *big.Int) {
	var buffer [32]byte
	if n != nil {
		var bufint uint256.Int // No pointer, alloc free
		bufint.SetFromBig(n)
		bufint.MarshalSSZInto(buffer[:])
	}
	h.insertChunk(buffer, 0)
}

// TreeStaticBytes trees a static binary blob.
//
// The blob is passed by pointer to avoid high stack copy costs and a potential
// escape to the heap.
func TreeStaticBytes[T commonBytesLengths](h *Treerer, blob *T) {
	// The code below should have used `blob[:]`, alas Go's generics compiler
	// is missing that (i.e. a bug): https://github.com/golang/go/issues/51740
	h.treeBytes(unsafe.Slice(&(*blob)[0], len(*blob)))
}

// TreeCheckedStaticBytes trees a static binary blob.
func TreeCheckedStaticBytes(h *Treerer, blob []byte) {
	h.treeBytes(blob)
}

// TreeDynamicBytes trees a dynamic binary blob.
func TreeDynamicBytes(h *Treerer, blob []byte, maxSize uint64) {
	h.descendMixinLayer()
	h.insertBlobChunks(blob)
	h.ascendMixinLayer(uint64(len(blob)), (maxSize+31)/32)
}

// TreeStaticObject trees a static ssz object.
func TreeStaticObject(h *Treerer, obj StaticObject) {
	h.descendLayer()
	obj.DefineSSZ(h.codec)
	h.ascendLayer(0)
}

// TreeDynamicObject trees a dynamic ssz object.
func TreeDynamicObject(h *Treerer, obj DynamicObject) {
	h.descendLayer()
	obj.DefineSSZ(h.codec)
	h.ascendLayer(0)
}

// TreeArrayOfBits trees a static array of (packed) bits.
func TreeArrayOfBits[T commonBitsLengths](h *Treerer, bits *T) {
	// The code below should have used `*bits[:]`, alas Go's generics compiler
	// is missing that (i.e. a bug): https://github.com/golang/go/issues/51740
	h.treeBytes(unsafe.Slice(&(*bits)[0], len(*bits)))
}

// TreeSliceOfBits trees a dynamic slice of (packed) bits.
func TreeSliceOfBits(h *Treerer, bits bitfield.Bitlist, maxBits uint64) {
	// Parse the bit-list into a treeable representation
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

// TreeArrayOfUint64s trees a static array of uint64s.
//
// The reason the ns is passed by pointer and not by value is to prevent it from
// escaping to the heap (and incurring an allocation) when passing it to the
// treerer.
func TreeArrayOfUint64s[T commonUint64sLengths](h *Treerer, ns *T) {
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

// TreeSliceOfUint64s trees a dynamic slice of uint64s.
func TreeSliceOfUint64s[T ~uint64](h *Treerer, ns []T, maxItems uint64) {
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

// TreeArrayOfStaticBytes trees a static array of static binary blobs.
//
// The reason the blobs is passed by pointer and not by value is to prevent it
// from escaping to the heap (and incurring an allocation) when passing it to
// the output stream.
func TreeArrayOfStaticBytes[T commonBytesArrayLengths[U], U commonBytesLengths](h *Treerer, blobs *T) {
	// The code below should have used `(*blobs)[:]`, alas Go's generics compiler
	// is missing that (i.e. a bug): https://github.com/golang/go/issues/51740
	TreeUnsafeArrayOfStaticBytes(h, unsafe.Slice(&(*blobs)[0], len(*blobs)))
}

// TreeUnsafeArrayOfStaticBytes trees a static array of static binary blobs.
func TreeUnsafeArrayOfStaticBytes[T commonBytesLengths](h *Treerer, blobs []T) {
	h.descendLayer()
	for i := 0; i < len(blobs); i++ {
		// The code below should have used `blobs[i][:]`, alas Go's generics compiler
		// is missing that (i.e. a bug): https://github.com/golang/go/issues/51740
		h.treeBytes(unsafe.Slice(&blobs[i][0], len(blobs[i])))
	}
	h.ascendLayer(0)
}

// TreeCheckedArrayOfStaticBytes trees a static array of static binary blobs.
func TreeCheckedArrayOfStaticBytes[T commonBytesLengths](h *Treerer, blobs []T) {
	h.descendLayer()
	for i := 0; i < len(blobs); i++ {
		// The code below should have used `blobs[i][:]`, alas Go's generics compiler
		// is missing that (i.e. a bug): https://github.com/golang/go/issues/51740
		h.treeBytes(unsafe.Slice(&blobs[i][0], len(blobs[i])))
	}
	h.ascendLayer(0)
}

// TreeSliceOfStaticBytes trees a dynamic slice of static binary blobs.
func TreeSliceOfStaticBytes[T commonBytesLengths](h *Treerer, blobs []T, maxItems uint64) {
	h.descendMixinLayer()
	for i := 0; i < len(blobs); i++ {
		// The code below should have used `blobs[i][:]`, alas Go's generics compiler
		// is missing that (i.e. a bug): https://github.com/golang/go/issues/51740
		h.treeBytes(unsafe.Slice(&blobs[i][0], len(blobs[i])))
	}
	h.ascendMixinLayer(uint64(len(blobs)), maxItems)
}

// TreeSliceOfDynamicBytes trees a dynamic slice of dynamic binary blobs.
func TreeSliceOfDynamicBytes(h *Treerer, blobs [][]byte, maxItems uint64, maxSize uint64) {
	h.descendMixinLayer()
	for _, blob := range blobs {
		h.descendMixinLayer()
		h.insertBlobChunks(blob)
		h.ascendMixinLayer(uint64(len(blob)), (maxSize+31)/32)
	}
	h.ascendMixinLayer(uint64(len(blobs)), maxItems)
}

// TreeSliceOfStaticObjects trees a dynamic slice of static ssz objects.
func TreeSliceOfStaticObjects[T StaticObject](h *Treerer, objects []T, maxItems uint64) {
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
func TreeSliceOfDynamicObjects[T DynamicObject](h *Treerer, objects []T, maxItems uint64) {
	h.descendMixinLayer()
	for _, obj := range objects {
		h.descendLayer()
		obj.DefineSSZ(h.codec)
		h.ascendLayer(0)
	}
	h.ascendMixinLayer(uint64(len(objects)), maxItems)
}

// treeBytes either appends the blob to the hasher's scratch space if it's small
// enough to fit into a single chunk, or chunks it up and merkleizes it first.
func (h *Treerer) treeBytes(blob []byte) {
	// If the blob is small, accumulate as a single chunk
	if len(blob) <= 32 {
		var buffer [32]byte
		copy(buffer[:], blob)
		h.insertChunk(buffer, 0)
		return
	}
	// Otherwise hash it as its own tree
	h.descendLayer()
	h.insertBlobChunks(blob)
	h.ascendLayer(0)
}

// insertChunk adds a chunk to the accumulators, collapsing matching pairs.
func (h *Treerer) insertChunk(chunk [32]byte, depth int) {
	// Create a new leaf node
	newNode := &Node{Hash: chunk}

	// Insert the node into the accumulator
	h.nodes = append(h.nodes, newNode)

	// Insert the chunk into the accumulator
	h.chunks = append(h.chunks, chunk)

	// If the depth tracker is at the leaf level, bump the leaf count
	groups := len(h.groups)
	if groups > 0 && h.groups[groups-1].layer == h.layer && h.groups[groups-1].depth == depth {
		h.groups[groups-1].chunks++
	} else {
		// New leaf group, create it and early return. Nothing to hash with only
		// one leaf in our chunk list.
		h.groups = append(h.groups, groupStats{
			layer:  h.layer,
			depth:  depth,
			chunks: 1,
		})
		return
	}
	// Leaf counter incremented, if not yet enough for a hashing round, return
	group := h.groups[groups-1]
	if group.chunks != hasherBatch {
		return
	}
	for {

		// We've reached exactly the batch number of chunks
		nodes := len(h.nodes)
		for i := nodes - hasherBatch; i < nodes; i += 2 {
			left := h.nodes[i]
			right := h.nodes[i+1]

			parentHash := [][32]byte{[32]byte{}}
			gohashtree.HashChunks(parentHash, [][32]byte{left.Hash, right.Hash})

			parent := &Node{
				Hash:  parentHash[0],
				Left:  left,
				Right: right,
			}

			left.Parent = parent
			right.Parent = parent

			h.nodes[i/2] = parent
		}
		h.nodes = h.nodes[:nodes-hasherBatch/2]

		// We've reached **exactly** the batch number of chunks. Note, we're adding
		// them one by one, so can't all of a sudden overshoot. Hash the next batch
		// of chunks and update the trackers.
		chunks := len(h.chunks)
		gohashtree.HashChunks(h.chunks[chunks-hasherBatch:], h.chunks[chunks-hasherBatch:])
		h.chunks = h.chunks[:chunks-hasherBatch/2]

		group.depth++
		group.chunks >>= 1

		// The last group tracker we've just hashed needs to be either updated to
		// the new level count, or merged into the previous one if they share all
		// the layer/depth params.
		if groups > 1 {
			prev := h.groups[groups-2]
			if prev.layer == group.layer && prev.depth == group.depth {
				// Two groups can be merged, will trigger a new collapse round
				prev.chunks += group.chunks
				group = prev

				groups--
				continue
			}
		}
		// Either have a single group, or the previous is from a different layer
		// or depth level, update the tail and return
		h.groups = h.groups[:groups]
		h.groups[groups-1] = group
		return
	}
}

func (h *Treerer) Root() *Node {
	return h.root
}

// insertBlobChunks splits up the blob into 32 byte chunks and adds them to the
// accumulators, collapsing matching pairs.
func (h *Treerer) insertBlobChunks(blob []byte) {
	var buffer [32]byte
	for len(blob) >= 32 {
		copy(buffer[:], blob)
		h.insertChunk(buffer, 0)
		blob = blob[32:]
	}
	if len(blob) > 0 {
		buffer = [32]byte{}
		copy(buffer[:], blob)
		h.insertChunk(buffer, 0)
	}
}

// descendLayer starts a new hashing layer, acting as a barrier to prevent the
// chunks from being collapsed into previous pending ones.
func (h *Treerer) descendLayer() {
	h.layer++
}

// descendMixinLayer is similar to descendLayer, but actually descends two at the
// same time, using the outer for mixing in a list length during ascent.
func (h *Treerer) descendMixinLayer() {
	h.layer += 2
}

// ascendLayer terminates a hashing layer, moving the result up one level and
// collapsing anything unblocked. The capacity param controls how many chunks
// a dynamic list is expected to be composed of at maximum (0 == only balance).
func (h *Treerer) ascendLayer(capacity uint64) {
	// Before even considering extending the layer to capacity, balance any
	// partial sub-tries to their completion.
	h.balanceLayer()

	h.root = h.nodes[len(h.nodes)-1]
	h.nodes = h.nodes[:len(h.nodes)-1]

	// Last group was reduced to a single root hash. If the capacity used during
	// hashing it was less than what the container slot required, keep expanding
	// it with empty sibling tries.
	for {
		groups := len(h.groups)

		// If we've used up the required capacity, stop expanding
		group := h.groups[groups-1]
		if (1 << group.depth) >= capacity {
			break
		}
		// Last group requires expansion, hash in a new empty sibling trie
		h.chunks = append(h.chunks, hasherZeroCache[group.depth])

		chunks := len(h.chunks)
		gohashtree.HashChunks(h.chunks[chunks-2:], h.chunks[chunks-2:])
		h.chunks = h.chunks[:chunks-1]

		h.groups[groups-1].depth++
	}
	// Ascend from the previous hashing layer
	h.layer--

	chunks := len(h.chunks)
	root := h.chunks[chunks-1]
	h.chunks = h.chunks[:chunks-1]

	groups := len(h.groups)
	h.groups = h.groups[:groups-1]

	h.insertChunk(root, 0)
}

// balanceLayer can be used to take a partial hashing result of an unbalanced
// trie and append enough empty chunks (virtually) at the end to collapse it
// down to a single root.
func (h *Treerer) balanceLayer() {
	// If the layer is incomplete, append in zero chunks. First up, before even
	// caring about maximum length, we must balance the tree (i.e. reduce it to
	// a single root hash).
	for {
		groups := len(h.groups)

		// If the last layer was reduced to one root, we've balanced the tree
		group := h.groups[groups-1]
		if group.chunks == 1 {
			if groups == 1 || h.groups[groups-2].layer != group.layer {
				return
			}
		}
		// Either group has multiple chunks still, or there are multiple entire
		// groups in this layer. Either way, we need to collapse this group into
		// the previous one and then see.
		if group.chunks&0x1 == 1 {
			// Group unbalanced, expand with a zero sub-trie
			zeroNode := &Node{Hash: hasherZeroCache[group.depth]}
			h.nodes = append(h.nodes, zeroNode)
			group.chunks++
		}

		nodes := len(h.nodes)
		for i := nodes - int(group.chunks); i < nodes; i += 2 {
			left := h.nodes[i]
			right := h.nodes[i+1]

			parentHash := [][32]byte{[32]byte{}}
			gohashtree.HashChunks(parentHash, [][32]byte{left.Hash, right.Hash})

			parent := &Node{
				Hash:  parentHash[0],
				Left:  left,
				Right: right,
			}
			left.Parent = parent
			right.Parent = parent

			h.nodes[i/2] = parent
		}
		h.nodes = h.nodes[:nodes-int(group.chunks)/2]

		chunks := len(h.chunks)
		gohashtree.HashChunks(h.chunks[chunks-int(group.chunks):], h.chunks[chunks-int(group.chunks):])
		h.chunks = h.chunks[:chunks-int(group.chunks)>>1]

		group.depth++
		group.chunks >>= 1

		// The last group tracker we've just hashed needs to be either updated to
		// the new level count, or merged into the previous one if they share all
		// the layer/depth params.
		if groups > 1 {
			prev := h.groups[groups-2]
			if prev.layer == group.layer && prev.depth == group.depth {
				// Two groups can be merged, may trigger a new collapse round
				h.groups[groups-2].chunks += group.chunks
				h.groups = h.groups[:groups-1]
				continue
			}
		}
		// Either have a single group, or the previous is from a different layer
		// or depth level, update the tail and see if more balancing is needed
		h.groups[groups-1] = group
	}
}

// ascendMixinLayer is similar to ascendLayer, but actually ascends one for the
// data content, and then mixes in the provided length and ascends once more.
func (h *Treerer) ascendMixinLayer(size uint64, chunks uint64) {
	// If no items have been added, there's nothing to ascend out of. Fix that
	// corner-case here.
	var buffer [32]byte
	if size == 0 {
		h.insertChunk(buffer, 0)
	}
	h.ascendLayer(chunks) // data content

	binary.LittleEndian.PutUint64(buffer[:8], size)
	h.insertChunk(buffer, 0)

	h.ascendLayer(0) // length mixin
}

// Reset resets the Treerer obj
func (h *Treerer) Reset() {
	h.chunks = h.chunks[:0]
	h.groups = h.groups[:0]
	h.threads = false

	h.nodes = h.nodes[:0]
	h.root = nil
}
