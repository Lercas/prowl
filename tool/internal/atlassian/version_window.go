package atlassian

import (
	"container/heap"
	"sort"
)

type versionHeap []int

func (h versionHeap) Len() int           { return len(h) }
func (h versionHeap) Less(i, j int) bool { return h[i] < h[j] }
func (h versionHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *versionHeap) Push(v any)        { *h = append(*h, v.(int)) }
func (h *versionHeap) Pop() any {
	v := (*h)[len(*h)-1]
	*h = (*h)[:len(*h)-1]
	return v
}

// boundedVersions retains the highest distinct positive numbers without keeping every listed
// version. Once an older number has left the window, no future number can bring it back.
type boundedVersions struct {
	limit  int
	nums   versionHeap
	seen   map[int]bool
	capped bool
}

func newBoundedVersions(limit int) *boundedVersions {
	return &boundedVersions{limit: limit, seen: make(map[int]bool)}
}

func (v *boundedVersions) add(n int) {
	if n <= 0 || v.seen[n] {
		return
	}
	if len(v.nums) >= v.limit {
		v.capped = true
		if v.limit <= 0 || n <= v.nums[0] {
			return
		}
		delete(v.seen, v.nums[0])
		v.nums[0] = n
		heap.Fix(&v.nums, 0)
	} else {
		heap.Push(&v.nums, n)
	}
	v.seen[n] = true
}

func (v *boundedVersions) window() ([]int, bool) {
	// Return an independent, sorted slice: callers may filter it without changing the heap.
	nums := append([]int(nil), v.nums...)
	sort.Ints(nums)
	return nums, v.capped
}

func (v *boundedVersions) listing(err error) ([]int, bool, error) {
	nums, capped := v.window()
	return nums, capped, err
}
