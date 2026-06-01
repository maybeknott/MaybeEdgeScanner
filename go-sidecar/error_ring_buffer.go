package main

type errorRingBuffer struct {
	storage []string
	cursor  int
	full    bool
}

func newErrorRingBuffer(capacity int) *errorRingBuffer {
	if capacity < 1 {
		capacity = 1
	}
	return &errorRingBuffer{storage: make([]string, capacity)}
}

func (rb *errorRingBuffer) Append(errText string) {
	if rb == nil || len(rb.storage) == 0 {
		return
	}
	rb.storage[rb.cursor] = errText
	rb.cursor = (rb.cursor + 1) % len(rb.storage)
	if rb.cursor == 0 {
		rb.full = true
	}
}

func (rb *errorRingBuffer) Snapshot() []string {
	if rb == nil || len(rb.storage) == 0 {
		return nil
	}
	count := rb.cursor
	start := 0
	if rb.full {
		count = len(rb.storage)
		start = rb.cursor
	}
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		errText := rb.storage[(start+i)%len(rb.storage)]
		if errText != "" {
			out = append(out, errText)
		}
	}
	return out
}
