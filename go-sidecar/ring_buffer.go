package main

import (
	"runtime"
	"sync/atomic"
)

type RingBufferNode[T any] struct {
	val  T
	free uint32 // 0: empty, 1: occupied
}

type RingBuffer[T any] struct {
	buffer []RingBufferNode[T]
	mask   uint32
	write  uint32
	read   uint32
}

func NewRingBuffer[T any](capacity uint32) *RingBuffer[T] {
	var size uint32 = 1
	for size < capacity {
		size <<= 1
	}
	return &RingBuffer[T]{
		buffer: make([]RingBufferNode[T], size),
		mask:   size - 1,
	}
}

func (rb *RingBuffer[T]) Push(val T) bool {
	for {
		w := atomic.LoadUint32(&rb.write)
		r := atomic.LoadUint32(&rb.read)
		if w-r >= uint32(len(rb.buffer)) {
			return false
		}
		idx := w & rb.mask
		node := &rb.buffer[idx]
		if atomic.LoadUint32(&node.free) == 0 {
			if atomic.CompareAndSwapUint32(&rb.write, w, w+1) {
				node.val = val
				atomic.StoreUint32(&node.free, 1)
				return true
			}
		}
		runtime.Gosched()
	}
}

func (rb *RingBuffer[T]) Pop() (T, bool) {
	for {
		r := atomic.LoadUint32(&rb.read)
		w := atomic.LoadUint32(&rb.write)
		if r == w {
			var zero T
			return zero, false
		}
		idx := r & rb.mask
		node := &rb.buffer[idx]
		if atomic.LoadUint32(&node.free) == 1 {
			if atomic.CompareAndSwapUint32(&rb.read, r, r+1) {
				val := node.val
				var zero T
				node.val = zero
				atomic.StoreUint32(&node.free, 0)
				return val, true
			}
		}
		runtime.Gosched()
	}
}
