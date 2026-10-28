package mlmodel

import (
	"errors"
	"fmt"
)

// validateTree checks every node, including unreachable nodes, before allocating inference arrays.
// Iterative DFS bounds stack use for dense or deeply nested trees; completed subgraphs are visited
// once, so shared children are legal and do not multiply validation work.
func validateTree(tree *rawTree) error {
	for i, leaf := range tree.IsLeaf {
		if (leaf != 0 && leaf != 1) || (tree.MissingLeft[i] != 0 && tree.MissingLeft[i] != 1) {
			return fmt.Errorf("node %d has invalid boolean flags", i)
		}
		if leaf == 0 {
			if idx := tree.FeatureIdx[i]; idx < 0 || idx >= NumFeatures {
				return fmt.Errorf("node %d has an invalid feature index", i)
			}
			if tree.Left[i] < 0 || tree.Left[i] >= len(tree.IsLeaf) || tree.Right[i] < 0 || tree.Right[i] >= len(tree.IsLeaf) {
				return fmt.Errorf("node %d has an invalid child index", i)
			}
		}
	}
	type frame struct {
		node int
		exit bool
	}
	colors := make([]uint8, len(tree.IsLeaf))
	var stack []frame
	for start := range tree.IsLeaf {
		if colors[start] != 0 {
			continue
		}
		stack = append(stack[:0], frame{node: start})
		for len(stack) > 0 {
			current := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if current.exit {
				colors[current.node] = 2
				continue
			}
			switch colors[current.node] {
			case 1:
				return ErrCyclicModel
			case 2:
				continue
			}
			colors[current.node] = 1
			stack = append(stack, frame{node: current.node, exit: true})
			if tree.IsLeaf[current.node] == 0 {
				stack = append(stack, frame{node: tree.Right[current.node]}, frame{node: tree.Left[current.node]})
			}
		}
	}
	if len(colors) == 0 {
		return errors.New("tree has no nodes")
	}
	return nil
}
