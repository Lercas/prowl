// Package ahocorasick is a multi-pattern substring matcher: it finds which of N patterns occur in a
// text in a single pass over the bytes, replacing N separate strings.Contains scans.
package ahocorasick

// Matcher is a compiled pattern set, read-only and goroutine-safe after New.
type Matcher struct {
	next []int32   // flat goto table: node<<8 | byte -> next node
	out  [][]int32 // per node: matched pattern ids
	n    int
}

// PatternCount returns how many patterns were compiled.
func (m *Matcher) PatternCount() int { return m.n }

// Transitions exposes the flat goto table; callers index it directly as next[cur<<8 | b].
func (m *Matcher) Transitions() []int32 { return m.next }

// Outputs exposes the per-node matched pattern ids (parallel to Transitions).
func (m *Matcher) Outputs() [][]int32 { return m.out }

type buildNode struct {
	next [256]int32
	out  []int32
	fail int32
}

// New compiles the patterns into a goto automaton; pattern id == index in the slice.
func New(patterns []string) *Matcher {
	nodes := []buildNode{newBuildNode()}
	for id, p := range patterns {
		if p == "" {
			continue
		}
		cur := int32(0)
		for i := 0; i < len(p); i++ {
			c := p[i]
			if nodes[cur].next[c] < 0 {
				nodes = append(nodes, newBuildNode())
				nodes[cur].next[c] = int32(len(nodes) - 1)
			}
			cur = nodes[cur].next[c]
		}
		nodes[cur].out = append(nodes[cur].out, int32(id))
	}
	queue := make([]int32, 0, len(nodes))
	for c := 0; c < 256; c++ {
		if nodes[0].next[c] < 0 {
			nodes[0].next[c] = 0
		} else {
			ch := nodes[0].next[c]
			nodes[ch].fail = 0
			queue = append(queue, ch)
		}
	}
	// BFS by depth so each node's fail link points at an already-processed shallower node
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for c := 0; c < 256; c++ {
			v := nodes[u].next[c]
			goTo := nodes[nodes[u].fail].next[c]
			if v < 0 {
				nodes[u].next[c] = goTo
				continue
			}
			nodes[v].fail = goTo
			nodes[v].out = append(nodes[v].out, nodes[goTo].out...)
			queue = append(queue, v)
		}
	}
	// flatten into a contiguous transition table
	m := &Matcher{next: make([]int32, len(nodes)*256), out: make([][]int32, len(nodes)), n: len(patterns)}
	for i := range nodes {
		copy(m.next[i*256:i*256+256], nodes[i].next[:])
		m.out[i] = nodes[i].out
	}
	return m
}

func newBuildNode() buildNode {
	var nd buildNode
	for i := range nd.next {
		nd.next[i] = -1
	}
	return nd
}

// MatchInto sets present[id]=true for every pattern id found in text, in one O(len) pass.
// present must have length >= PatternCount() and is owned by the caller.
func (m *Matcher) MatchInto(text string, present []bool) {
	next, out := m.next, m.out
	var cur int32
	for i := 0; i < len(text); i++ {
		cur = next[cur<<8|int32(text[i])]
		for _, id := range out[cur] {
			present[id] = true
		}
	}
}
