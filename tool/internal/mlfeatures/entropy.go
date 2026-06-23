// Package mlfeatures is a Go port of the Python ML feature extractor
// (src/features/extract.py and entropy.py) used to score candidate secret
// strings, so the Python-trained model can run from the scanner binary.
// Functions operate on runes to match Python str code points over the ASCII/BMP
// ranges the model was trained on.
package mlfeatures

import (
	"math"
)

// Alphabets, mirroring src/features/entropy.py. These are sets of runes.
var (
	base64Alphabet = makeSet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
	hexAlphabet    = makeSet("0123456789abcdefABCDEF")
	base32Alphabet = makeSet("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
)

func makeSet(s string) map[rune]struct{} {
	m := make(map[rune]struct{}, len(s))
	for _, r := range s {
		m[r] = struct{}{}
	}
	return m
}

// shannonEntropy returns Shannon entropy in bits/char over the empirical symbol
// distribution. Mirrors shannon_entropy().
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0.0
	}
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	h := 0.0
	fn := float64(n)
	for _, c := range counts {
		p := float64(c) / fn
		h -= p * math.Log2(p)
	}
	return h
}

// normalizedEntropy scales entropy to [0,1] by log2(distinct). Mirrors
// normalized_entropy().
func normalizedEntropy(s string) float64 {
	// len(s) in Python counts code points, so use rune count.
	if runeLen(s) < 2 {
		return 0.0
	}
	distinct := distinctRunes(s)
	if distinct < 2 {
		return 0.0
	}
	return shannonEntropy(s) / math.Log2(float64(distinct))
}

// alphabetEntropy computes entropy restricted to a fixed alphabet (detect-secrets
// style). Mirrors alphabet_entropy().
func alphabetEntropy(s string, alphabet map[rune]struct{}) float64 {
	if s == "" {
		return 0.0
	}
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		if _, ok := alphabet[r]; ok {
			counts[r]++
			n++
		}
	}
	if n == 0 {
		return 0.0
	}
	h := 0.0
	fn := float64(n)
	for _, c := range counts {
		p := float64(c) / fn
		h -= p * math.Log2(p)
	}
	return h
}

// bigramEntropy is the conditional entropy of the next char given the previous
// one. Mirrors bigram_entropy().
func bigramEntropy(s string) float64 {
	rs := []rune(s)
	if len(rs) < 3 {
		return 0.0
	}
	// bigrams over consecutive runes; firsts over the first rune of each bigram.
	bigrams := map[[2]rune]int{}
	firsts := map[rune]int{}
	for i := 0; i < len(rs)-1; i++ {
		bg := [2]rune{rs[i], rs[i+1]}
		bigrams[bg]++
		firsts[rs[i]]++
	}
	total := 0
	for _, c := range bigrams {
		total += c
	}
	ftotal := float64(total)
	h := 0.0
	for bg, c := range bigrams {
		pBg := float64(c) / ftotal
		pFirst := float64(firsts[bg[0]]) / ftotal
		h -= pBg * math.Log2(pBg/pFirst)
	}
	return h
}

// compressionRatio returns len(zlib(s)) / len(s) over UTF-8, mirroring
// compression_ratio() (Python zlib.compress at level 6). The compressed length
// comes from zlibCompressedLen: the cgo build (system zlib) is byte-exact; the
// nocgo build (Go compress/zlib) only approximates Python. See zlib_nocgo.go.
func compressionRatio(s string) float64 {
	if s == "" {
		return 0.0
	}
	raw := []byte(s) // Go strings are already UTF-8; "ignore" errors do not arise here.
	denom := len(raw)
	if denom < 1 {
		denom = 1
	}
	return float64(zlibCompressedLen(raw)) / float64(denom)
}

// charDiversity is distinct chars / length. Mirrors char_diversity().
func charDiversity(s string) float64 {
	if s == "" {
		return 0.0
	}
	return float64(distinctRunes(s)) / float64(runeLen(s))
}

func runeLen(s string) int {
	n := 0
	for range s {
		n++
	}
	return n
}

func distinctRunes(s string) int {
	seen := map[rune]struct{}{}
	for _, r := range s {
		seen[r] = struct{}{}
	}
	return len(seen)
}
