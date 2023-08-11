package metanode

import (
	"bytes"
	"encoding/json"
	"sync"

	"github.com/cubefs/cubefs/storage"

	"github.com/cubefs/cubefs/proto"
)

type SortedExtents struct {
	sync.RWMutex
	eks []proto.ExtentKey
}

func NewSortedExtents() *SortedExtents {
	return &SortedExtents{
		eks: make([]proto.ExtentKey, 0),
	}
}

// attention: only used for deleted eks
func NewSortedExtentsFromEks(eks []proto.ExtentKey) *SortedExtents {
	return &SortedExtents{
		eks: eks,
	}
}

func (se *SortedExtents) String() string {
	se.RLock()
	data, err := json.Marshal(se.eks)
	se.RUnlock()
	if err != nil {
		return ""
	}
	return string(data)
}

func (se *SortedExtents) MarshalBinary() ([]byte, error) {
	var data []byte

	se.RLock()
	defer se.RUnlock()

	data = make([]byte, 0, proto.ExtentLength*len(se.eks))
	ekdata := make([]byte, proto.ExtentLength)

	for _, ek := range se.eks {
		ek.MarshalBinaryExt(ekdata)
		data = append(data, ekdata...)
	}

	return data, nil
}

func (se *SortedExtents) UnmarshalBinary(data []byte) error {
	var ek proto.ExtentKey

	se.Lock()
	defer se.Unlock()

	buf := bytes.NewBuffer(data)
	for {
		if buf.Len() == 0 {
			break
		}
		if err := ek.UnmarshalBinary(buf); err != nil {
			return err
		}
		// Don't use se.Append here, since we need to retain the raw ek order.
		se.eks = append(se.eks, ek)
	}
	return nil
}

func (se *SortedExtents) Append(ek proto.ExtentKey) (deleteExtents []proto.ExtentKey) {
	endOffset := ek.FileOffset + uint64(ek.Size)

	se.Lock()
	defer se.Unlock()

	if len(se.eks) <= 0 {
		se.eks = append(se.eks, ek)
		return
	}
	lastKey := se.eks[len(se.eks)-1]
	if lastKey.FileOffset+uint64(lastKey.Size) <= ek.FileOffset {
		se.eks = append(se.eks, ek)
		return
	}
	firstKey := se.eks[0]
	if firstKey.FileOffset >= endOffset {
		eks := se.doCopyExtents()
		se.eks = se.eks[:0]
		se.eks = append(se.eks, ek)
		se.eks = append(se.eks, eks...)
		return
	}

	var startIndex, endIndex int

	invalidExtents := make([]proto.ExtentKey, 0)
	for idx, key := range se.eks {
		if ek.FileOffset > key.FileOffset {
			startIndex = idx + 1
			continue
		}
		if endOffset >= key.FileOffset+uint64(key.Size) {
			invalidExtents = append(invalidExtents, key)
			continue
		}
		break
	}

	endIndex = startIndex + len(invalidExtents)
	upperExtents := make([]proto.ExtentKey, len(se.eks)-endIndex)
	copy(upperExtents, se.eks[endIndex:])
	se.eks = se.eks[:startIndex]
	se.eks = append(se.eks, ek)
	se.eks = append(se.eks, upperExtents...)
	// check if ek and key are the same extent file with size extented
	deleteExtents = make([]proto.ExtentKey, 0, len(invalidExtents))
	for _, key := range invalidExtents {
		if key.PartitionId != ek.PartitionId || key.ExtentId != ek.ExtentId {
			deleteExtents = append(deleteExtents, key)
		}
	}
	return
}

func (se *SortedExtents) AppendWithCheck(ek proto.ExtentKey, discard []proto.ExtentKey) (deleteExtents []proto.ExtentKey, status uint8) {
	status = proto.OpOk
	endOffset := ek.FileOffset + uint64(ek.Size)

	se.Lock()
	defer se.Unlock()

	if len(se.eks) <= 0 {
		se.eks = append(se.eks, ek)
		return
	}
	lastKey := se.eks[len(se.eks)-1]
	if lastKey.FileOffset+uint64(lastKey.Size) <= ek.FileOffset {
		se.eks = append(se.eks, ek)
		return
	}
	firstKey := se.eks[0]
	if firstKey.FileOffset >= endOffset {
		se.insert(ek, 0)
		return
	}

	var startIndex, endIndex int

	invalidExtents := make([]proto.ExtentKey, 0)
	for idx, key := range se.eks {
		if ek.FileOffset > key.FileOffset {
			startIndex = idx + 1
			continue
		}
		if endOffset >= key.FileOffset+uint64(key.Size) {
			invalidExtents = append(invalidExtents, key)
			continue
		}
		break
	}

	// Makes the request idempotent, just in case client retries.
	if len(invalidExtents) == 1 && invalidExtents[0] == ek {
		return
	}

	// check if ek and key are the same extent file with size extented
	deleteExtents = make([]proto.ExtentKey, 0, len(invalidExtents))
	for _, key := range invalidExtents {
		if key.PartitionId != ek.PartitionId || key.ExtentId != ek.ExtentId || key.ExtentOffset != ek.ExtentOffset {
			deleteExtents = append(deleteExtents, key)
		}
	}

	//log.LogInfof("invalidExtents(%v) deleteExtents(%v) discardExtents(%v)", invalidExtents, deleteExtents, discard)

	if discard != nil {
		if len(deleteExtents) != len(discard) {
			return deleteExtents, proto.OpConflictExtentsErr
		}
		for i := 0; i < len(discard); i++ {
			if deleteExtents[i].PartitionId != discard[i].PartitionId || deleteExtents[i].ExtentId != discard[i].ExtentId || deleteExtents[i].ExtentOffset != discard[i].ExtentOffset {
				return deleteExtents, proto.OpConflictExtentsErr
			}
		}
	} else if len(deleteExtents) != 0 {
		return deleteExtents, proto.OpConflictExtentsErr
	}

	if len(invalidExtents) == 0 {
		se.insert(ek, startIndex)
		return
	}

	endIndex = startIndex + len(invalidExtents)
	se.instertWithDiscard(ek, startIndex, endIndex)
	return
}

func (se *SortedExtents) Truncate(offset uint64, doOnLastKey func(*proto.ExtentKey)) (deleteExtents []proto.ExtentKey) {
	var endIndex int

	se.Lock()
	defer se.Unlock()

	endIndex = -1
	for idx, key := range se.eks {
		if key.FileOffset >= offset {
			endIndex = idx
			break
		}
	}

	if endIndex < 0 {
		deleteExtents = make([]proto.ExtentKey, 0)
	} else {
		deleteExtents = make([]proto.ExtentKey, len(se.eks)-endIndex)
		copy(deleteExtents, se.eks[endIndex:])
		se.eks = se.eks[:endIndex]
	}

	numKeys := len(se.eks)
	if numKeys > 0 {
		lastKey := &se.eks[numKeys-1]
		if lastKey.FileOffset+uint64(lastKey.Size) > offset {
			if doOnLastKey != nil {
				doOnLastKey(&proto.ExtentKey{Size: uint32(lastKey.FileOffset + uint64(lastKey.Size) - offset)})
			}
			lastKey.Size = uint32(offset - lastKey.FileOffset)
		}
	}
	return
}

func (se *SortedExtents) insert(ek proto.ExtentKey, startIdx int) {
	se.eks = append(se.eks, ek)
	size := len(se.eks)

	for idx := size - 1; idx > startIdx; idx-- {
		se.eks[idx] = se.eks[idx-1]
	}

	se.eks[startIdx] = ek
}

func (se *SortedExtents) instertWithDiscard(ek proto.ExtentKey, startIdx, endIdx int) {
	upperSize := len(se.eks) - endIdx
	se.eks[startIdx] = ek

	for idx := 0; idx < upperSize; idx++ {
		se.eks[startIdx+1+idx] = se.eks[endIdx+idx]
	}

	se.eks = se.eks[:startIdx+1+upperSize]
}

func (se *SortedExtents) Len() int {
	se.RLock()
	defer se.RUnlock()
	return len(se.eks)
}

// Returns the file size
func (se *SortedExtents) LayerSize() (layerSize uint64) {
	se.RLock()
	defer se.RUnlock()

	last := len(se.eks)
	if last <= 0 {
		return uint64(0)
	}
	for _, ek := range se.eks {
		layerSize += uint64(ek.Size)
	}
	return
}

// Returns the file size
func (se *SortedExtents) Size() uint64 {
	se.RLock()
	defer se.RUnlock()

	last := len(se.eks)
	if last <= 0 {
		return uint64(0)
	}
	return se.eks[last-1].FileOffset + uint64(se.eks[last-1].Size)
}

func (se *SortedExtents) Range(f func(ek proto.ExtentKey) bool) {
	se.RLock()
	defer se.RUnlock()

	for _, ek := range se.eks {
		if !f(ek) {
			break
		}
	}
}

func (se *SortedExtents) Clone() *SortedExtents {
	newSe := NewSortedExtents()

	se.RLock()
	defer se.RUnlock()

	newSe.eks = se.doCopyExtents()
	return newSe
}

func (se *SortedExtents) CopyExtents() []proto.ExtentKey {
	se.RLock()
	defer se.RUnlock()
	return se.doCopyExtents()
}

func (se *SortedExtents) CopyTinyExtents() []proto.ExtentKey {
	se.RLock()
	defer se.RUnlock()
	return se.doCopyTinyExtents()
}

func (se *SortedExtents) doCopyExtents() []proto.ExtentKey {
	eks := make([]proto.ExtentKey, len(se.eks))
	copy(eks, se.eks)
	return eks
}

func (se *SortedExtents) doCopyTinyExtents() []proto.ExtentKey {
	eks := make([]proto.ExtentKey, 0)
	for _, ek := range se.eks {
		if storage.IsTinyExtent(ek.ExtentId) {
			eks = append(eks, ek)
		}
	}
	return eks
}

// discard code
func (se *SortedExtents) Delete(delEks []proto.ExtentKey) (curEks []proto.ExtentKey) {
	se.RLock()
	defer se.RUnlock()

	curEks = make([]proto.ExtentKey, len(se.eks)-len(delEks))
	for _, key := range se.eks {
		delFlag := false
		for _, delKey := range delEks {
			if key.FileOffset == delKey.ExtentOffset && key.ExtentId == delKey.ExtentId &&
				key.ExtentOffset == delKey.ExtentOffset && key.PartitionId == delKey.PartitionId &&
				key.Size == delKey.Size {
				delFlag = true
				break
			}
		}
		if !delFlag {
			curEks = append(curEks, key)
		}
	}
	se.eks = curEks
	return
}
