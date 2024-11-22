package detector

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestNewSynFloodDetector(t *testing.T) {
	tests := []struct {
		name       string
		windowSize time.Duration
		numWindows int
		width      uint32
		depth      uint32
		threshold  uint32
	}{
		{
			name:       "basic detector",
			windowSize: time.Second,
			numWindows: 2,
			width:      1000,
			depth:      4,
			threshold:  100,
		},
		{
			name:       "minimal detector",
			windowSize: time.Millisecond,
			numWindows: 1,
			width:      1,
			depth:      1,
			threshold:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewSynFloodDetector(tt.windowSize, tt.numWindows, tt.width, tt.depth, tt.threshold)
			if d == nil {
				t.Fatal("Expected non-nil detector")
			}
			if len(d.sketches) != tt.numWindows {
				t.Errorf("Got %d sketches, want %d", len(d.sketches), tt.numWindows)
			}
			if d.threshold != tt.threshold {
				t.Errorf("Got threshold %d, want %d", d.threshold, tt.threshold)
			}
		})
	}
}

func TestCMSketch(t *testing.T) {
	s := NewCMSketch(1000, 4)
	if s == nil {
		t.Fatal("Expected non-nil sketch")
	}

	// Test Add and Estimate
	ip := net.ParseIP("192.0.2.1").To4()
	if ip == nil {
		t.Fatal("Failed to parse IP")
	}

	// Initial count should be 0
	if count := s.Estimate(ip); count != 0 {
		t.Errorf("Initial count should be 0, got %d", count)
	}

	// Add once
	s.Add(ip)
	if count := s.Estimate(ip); count != 1 {
		t.Errorf("Count after one add should be 1, got %d", count)
	}

	// Test Reset
	s.Reset()
	if count := s.Estimate(ip); count != 0 {
		t.Errorf("Count after reset should be 0, got %d", count)
	}
}

func TestSynFloodDetection(t *testing.T) {
	// Create a detector with small numbers for testing
	d := NewSynFloodDetector(10*time.Millisecond, 2, 100, 4, 3)
	ip := net.ParseIP("192.0.2.1").To4()

	// Should not be flooding initially
	if d.IsFlooding(ip) {
		t.Error("Should not detect flooding before any SYNs")
	}

	// Add SYNs up to threshold
	for i := 0; i < 3; i++ {
		d.AddSyn(ip)
	}

	// Should detect flooding
	if !d.IsFlooding(ip) {
		t.Error("Should detect flooding after threshold exceeded")
	}

	// Test window rotation
	time.Sleep(11 * time.Millisecond) // Wait for window rotation
	d.AddSyn(ip)                      // This should go to new window

	// Should still be flooding (counts from both windows)
	if !d.IsFlooding(ip) {
		t.Error("Should still detect flooding across windows")
	}

	// Wait for first window to expire
	time.Sleep(11 * time.Millisecond)
	// Force rotation
	d.rotateIfNeeded()

	// Should no longer be flooding (old window rotated out)
	if d.IsFlooding(ip) {
		t.Error("Should not detect flooding after window rotation")
	}
}

func TestMultipleIPs(t *testing.T) {
	d := NewSynFloodDetector(time.Second, 2, 100, 4, 3)
	ip1 := net.ParseIP("192.0.2.1").To4()
	ip2 := net.ParseIP("192.0.2.2").To4()

	// Add SYNs for first IP
	for i := 0; i < 3; i++ {
		d.AddSyn(ip1)
	}

	// Check that only first IP is flooding
	if !d.IsFlooding(ip1) {
		t.Error("IP1 should be flooding")
	}
	if d.IsFlooding(ip2) {
		t.Error("IP2 should not be flooding")
	}

	// Add SYNs for second IP
	for i := 0; i < 3; i++ {
		d.AddSyn(ip2)
	}

	// Both should be flooding
	if !d.IsFlooding(ip1) {
		t.Error("IP1 should still be flooding")
	}
	if !d.IsFlooding(ip2) {
		t.Error("IP2 should now be flooding")
	}
}

func TestWindowRotation(t *testing.T) {
	d := NewSynFloodDetector(10*time.Millisecond, 3, 100, 4, 5)
	ip := net.ParseIP("192.0.2.1").To4()

	// Add SYNs in first window
	d.AddSyn(ip)
	d.AddSyn(ip)

	initialWindow := d.currentWindow

	// Wait for rotation
	time.Sleep(11 * time.Millisecond)
	d.rotateIfNeeded()

	if d.currentWindow == initialWindow {
		t.Error("Window should have rotated")
	}

	// Add more SYNs in new window
	d.AddSyn(ip)
	d.AddSyn(ip)

	// Total should be 4 (not flooding yet)
	if d.IsFlooding(ip) {
		t.Error("Should not be flooding with 4 SYNs across windows")
	}

	// Add one more to exceed threshold
	d.AddSyn(ip)
	if !d.IsFlooding(ip) {
		t.Error("Should be flooding after 5 SYNs")
	}
}

// Benchmarks
func BenchmarkAddSyn_SingleIP(b *testing.B) {
	d := NewSynFloodDetector(time.Second, 2, 1000, 4, 100)
	ip := net.ParseIP("192.0.2.1").To4()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.AddSyn(ip)
	}
}

// Benchmark adding SYNs from different IPs
func BenchmarkAddSyn_MultipleIPs(b *testing.B) {
	d := NewSynFloodDetector(time.Second, 2, 1000, 4, 100)
	// Pre-generate IPs to avoid IP generation overhead in benchmark
	ips := make([]net.IP, 1000)
	for i := range ips {
		ips[i] = net.IPv4(192, 0, byte(i/256), byte(i%256)).To4()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.AddSyn(ips[i%len(ips)])
	}
}

// Benchmark flood checking for a single IP
func BenchmarkIsFlooding_SingleIP(b *testing.B) {
	d := NewSynFloodDetector(time.Second, 2, 1000, 4, 100)
	ip := net.ParseIP("192.0.2.1").To4()

	// Add some SYNs first
	for i := 0; i < 50; i++ {
		d.AddSyn(ip)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.IsFlooding(ip)
	}
}

// Benchmark flood checking with window rotation
func BenchmarkIsFlooding_WithRotation(b *testing.B) {
	d := NewSynFloodDetector(time.Nanosecond, 2, 1000, 4, 100) // Very small window to force rotation
	ip := net.ParseIP("192.0.2.1").To4()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.IsFlooding(ip)
	}
}

// Benchmark the CM Sketch operations directly
func BenchmarkCMSketch_Add(b *testing.B) {
	s := NewCMSketch(1000, 4)
	ip := net.ParseIP("192.0.2.1").To4()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Add(ip)
	}
}

func BenchmarkCMSketch_Estimate(b *testing.B) {
	s := NewCMSketch(1000, 4)
	ip := net.ParseIP("192.0.2.1").To4()

	// Add some data first
	for i := 0; i < 50; i++ {
		s.Add(ip)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Estimate(ip)
	}
}

// Benchmark different sketch sizes
func BenchmarkCMSketch_DifferentSizes(b *testing.B) {
	sizes := []struct {
		width uint32
		depth uint32
	}{
		{100, 2},
		{1000, 4},
		{10000, 8},
	}

	ip := net.ParseIP("192.0.2.1").To4()

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Width=%d_Depth=%d", size.width, size.depth), func(b *testing.B) {
			s := NewCMSketch(size.width, size.depth)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.Add(ip)
				s.Estimate(ip)
			}
		})
	}
}

// Benchmark memory pressure scenarios
func BenchmarkUnderMemoryPressure(b *testing.B) {
	// Create a lot of sketches to simulate memory pressure
	sketches := make([]*CMSketch, 100)
	for i := range sketches {
		sketches[i] = NewCMSketch(1000, 4)
	}

	d := NewSynFloodDetector(time.Second, 2, 1000, 4, 100)
	ip := net.ParseIP("192.0.2.1").To4()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.AddSyn(ip)
		d.IsFlooding(ip)
	}
}

func BenchmarkAccuracyVsSize(b *testing.B) {
	configs := []struct {
		name      string
		width     uint32
		depth     uint32
		numIPs    int
		synsPerIP int
	}{
		{"Speedtest-W4k-D4", 4000, 4, 200, 100},      // ~64KB
		{"Speedtest-W8k-D4", 8000, 4, 200, 100},      // ~128KB
		{"Speedtest-W8k-D5", 8000, 5, 200, 100},      // ~160KB
		{"Wide-W4k-D4", 4000, 4, 100, 100},           // ~64KB
		{"Medium-1kIPs-W10k-D5", 10000, 5, 1000, 50}, // ~200KB
	}

	for _, cfg := range configs {
		b.Run(cfg.name, func(b *testing.B) {
			s := NewCMSketch(cfg.width, cfg.depth)
			ips := make([]net.IP, cfg.numIPs)
			for i := range ips {
				ips[i] = net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i)).To4()
			}

			// Measure accuracy
			b.ReportMetric(0, "error_pct") // Custom metric
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				// Add known number of SYNs
				for _, ip := range ips {
					for k := 0; k < cfg.synsPerIP; k++ {
						s.Add(ip)
					}
				}

				// Calculate error rate
				var totalError float64
				for _, ip := range ips {
					est := s.Estimate(ip)
					error := float64(est-uint32(cfg.synsPerIP)) / float64(cfg.synsPerIP)
					totalError += error
				}
				avgError := (totalError / float64(cfg.numIPs)) * 100
				b.ReportMetric(avgError, "error_pct")

				s.Reset()
			}
		})
	}
}
