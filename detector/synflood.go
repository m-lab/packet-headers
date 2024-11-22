package detector

import (
	"hash"
	"net"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
)

type SynFloodDetector struct {
	sketches      []*CMSketch   // Array of Count-Min sketches for time windows
	windowSize    time.Duration // How long each sketch covers (e.g. 10s)
	numWindows    int           // Number of sliding windows to maintain
	currentWindow int           // Index of current active window
	threshold     uint32        // Max SYNs per source per window before flagging
	lastRotation  time.Time     // When we last rotated windows
	mu            sync.RWMutex
}

// Individual Count-Min sketch
type CMSketch struct {
	width  uint32        // Number of counters per row
	depth  uint32        // Number of rows (hash functions)
	counts [][]uint32    // The actual counter matrix
	hashes []hash.Hash64 // Hash functions for each row
}

// Constructor for flood detector
func NewSynFloodDetector(windowSize time.Duration, numWindows int, width, depth uint32, threshold uint32) *SynFloodDetector {
	sketches := make([]*CMSketch, numWindows)
	for i := 0; i < numWindows; i++ {
		sketches[i] = NewCMSketch(width, depth)
	}

	return &SynFloodDetector{
		sketches:      sketches,
		windowSize:    windowSize,
		numWindows:    numWindows,
		currentWindow: 0,
		threshold:     threshold,
		lastRotation:  time.Now(),
	}
}

// Add a SYN packet from an IP
func (d *SynFloodDetector) AddSyn(srcIP net.IP) {
	d.rotateIfNeeded()
	d.sketches[d.currentWindow].Add(srcIP)
}

// Check if an IP is currently flooding
func (d *SynFloodDetector) IsFlooding(srcIP net.IP) bool {
	d.rotateIfNeeded()
	// Sum estimates across all windows
	var total uint32
	for _, sketch := range d.sketches {
		total += sketch.Estimate(srcIP)
	}
	return total >= d.threshold
}

// Rotate windows periodically
func (d *SynFloodDetector) rotateIfNeeded() {
	now := time.Now()
	if now.Sub(d.lastRotation) < d.windowSize {
		return
	}

	// Reset next window and advance
	nextWindow := (d.currentWindow + 1) % d.numWindows
	d.sketches[nextWindow].Reset()
	d.currentWindow = nextWindow
	d.lastRotation = now
}

// Constructor for Count-Min sketch
func NewCMSketch(width, depth uint32) *CMSketch {
	counts := make([][]uint32, depth)
	for i := range counts {
		counts[i] = make([]uint32, width)
	}

	hashes := make([]hash.Hash64, depth)
	for i := range hashes {
		// Initialize with different seeds
		hashes[i] = xxhash.New()
		hashes[i].Write([]byte{byte(i)})
	}

	return &CMSketch{
		width:  width,
		depth:  depth,
		counts: counts,
		hashes: hashes,
	}
}

// Add an item to sketch
func (s *CMSketch) Add(item []byte) {
	for i := range s.hashes {
		s.hashes[i].Reset()
		s.hashes[i].Write(item)
		h := s.hashes[i].Sum64() % uint64(s.width)
		s.counts[i][h]++
	}
}

// Get estimated count for item
func (s *CMSketch) Estimate(item []byte) uint32 {
	var min uint32 = ^uint32(0) // Max uint32 value
	for i := range s.hashes {
		s.hashes[i].Reset()
		s.hashes[i].Write(item)
		h := s.hashes[i].Sum64() % uint64(s.width)
		if s.counts[i][h] < min {
			min = s.counts[i][h]
		}
	}
	return min
}

// Reset all counters in a sketch
func (s *CMSketch) Reset() {
	for i := range s.counts {
		for j := range s.counts[i] {
			s.counts[i][j] = 0
		}
	}
}
