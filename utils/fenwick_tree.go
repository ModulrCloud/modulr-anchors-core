package utils

import "encoding/hex"

type StakeFenwickTree struct {
	tree []uint64
	n    int
}

func NewStakeFenwickTree(stakes []uint64) *StakeFenwickTree {
	n := len(stakes)
	t := &StakeFenwickTree{tree: make([]uint64, n+1), n: n}
	copy(t.tree[1:], stakes)
	for i := 1; i <= n; i++ {
		parent := i + (i & (-i))
		if parent <= n {
			t.tree[parent] += t.tree[i]
		}
	}
	return t
}

func (t *StakeFenwickTree) Remove(idx int, stake uint64) {
	i := idx + 1
	for i <= t.n {
		t.tree[i] -= stake
		i += i & (-i)
	}
}

func (t *StakeFenwickTree) FindByWeight(r uint64) int {
	pos := 0
	bitMask := 1
	for bitMask <= t.n {
		bitMask <<= 1
	}
	bitMask >>= 1

	for bitMask > 0 {
		next := pos + bitMask
		if next <= t.n && t.tree[next] <= r {
			r -= t.tree[next]
			pos = next
		}
		bitMask >>= 1
	}
	return pos
}

func HashHexToUint64(hashHex string) uint64 {
	if len(hashHex) < 16 {
		return 0
	}
	b, err := hex.DecodeString(hashHex[:16])
	if err != nil {
		return 0
	}
	var r uint64
	for _, by := range b {
		r = (r << 8) | uint64(by)
	}
	return r
}
