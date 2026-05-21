package main

import (
	"sync"
	"testing"
)

func TestRingBufferBasic(t *testing.T) {
	rb := NewRingBuffer[int](4) // capacity gets rounded up to 4

	// Empty pop
	val, ok := rb.Pop()
	if ok || val != 0 {
		t.Errorf("expected empty pop to fail, got %v, %v", val, ok)
	}

	// Basic pushes
	if !rb.Push(10) {
		t.Error("failed to push 10")
	}
	if !rb.Push(20) {
		t.Error("failed to push 20")
	}
	if !rb.Push(30) {
		t.Error("failed to push 30")
	}
	if !rb.Push(40) {
		t.Error("failed to push 40")
	}

	// Push on full buffer
	if rb.Push(50) {
		t.Error("expected push on full buffer to fail")
	}

	// Pops
	val, ok = rb.Pop()
	if !ok || val != 10 {
		t.Errorf("expected 10, got %v, %v", val, ok)
	}
	val, ok = rb.Pop()
	if !ok || val != 20 {
		t.Errorf("expected 20, got %v, %v", val, ok)
	}

	// Push after pop
	if !rb.Push(50) {
		t.Error("failed to push 50 after popping")
	}

	val, ok = rb.Pop()
	if !ok || val != 30 {
		t.Errorf("expected 30, got %v, %v", val, ok)
	}
	val, ok = rb.Pop()
	if !ok || val != 40 {
		t.Errorf("expected 40, got %v, %v", val, ok)
	}
	val, ok = rb.Pop()
	if !ok || val != 50 {
		t.Errorf("expected 50, got %v, %v", val, ok)
	}

	// Empty again
	val, ok = rb.Pop()
	if ok || val != 0 {
		t.Errorf("expected empty pop to fail, got %v, %v", val, ok)
	}
}

func TestRingBufferConcurrency(t *testing.T) {
	const capacity = 16
	const numWriters = 4
	const numReaders = 4
	const itemsPerWriter = 1000

	rb := NewRingBuffer[int](capacity)

	var wgWrite sync.WaitGroup
	var wgRead sync.WaitGroup

	// Track popped counts
	received := make(map[int]int)
	var mu sync.Mutex

	// Start Readers
	wgRead.Add(numReaders)
	for r := 0; r < numReaders; r++ {
		go func() {
			defer wgRead.Done()
			for {
				val, ok := rb.Pop()
				if ok {
					if val == -1 {
						// Sentinel for finished writing
						break
					}
					mu.Lock()
					received[val]++
					mu.Unlock()
				}
			}
		}()
	}

	// Start Writers
	wgWrite.Add(numWriters)
	for w := 0; w < numWriters; w++ {
		wId := w
		go func() {
			defer wgWrite.Done()
			for i := 0; i < itemsPerWriter; i++ {
				item := wId*itemsPerWriter + i
				// Keep pushing until it succeeds
				for !rb.Push(item) {
					// Busy loop or yield, the Push method calls runtime.Gosched() internally
				}
			}
		}()
	}

	// Wait for writers to complete
	wgWrite.Wait()

	// Push sentinels to terminate readers
	for r := 0; r < numReaders; r++ {
		for !rb.Push(-1) {
		}
	}

	// Wait for readers to finish
	wgRead.Wait()

	// Verify all items received exactly once
	if len(received) != numWriters*itemsPerWriter {
		t.Errorf("expected to receive %d unique items, got %d", numWriters*itemsPerWriter, len(received))
	}
	for k, count := range received {
		if count != 1 {
			t.Errorf("item %d was received %d times, expected exactly 1", k, count)
		}
	}
}
