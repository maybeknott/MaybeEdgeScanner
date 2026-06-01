package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
)

func parseHTTPStatus(line string) int {
	parts := strings.Fields(line)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return 0
	}
	code, _ := strconv.Atoi(parts[1])
	return code
}

var readerPool = sync.Pool{New: func() any {
	return bufio.NewReaderSize(nil, 16*1024)
}}

func pooledReader(r io.Reader) *bufio.Reader {
	reader := readerPool.Get().(*bufio.Reader)
	reader.Reset(r)
	return reader
}

func putReader(reader *bufio.Reader) {
	reader.Reset(bytes.NewReader(nil))
	readerPool.Put(reader)
}

func readLimitedLine(reader *bufio.Reader, limit int) (string, error) {
	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				line = append(line, chunk...)
				if len(line) >= limit {
					return "", errors.New("line too long")
				}
				continue
			}
			line = append(line, chunk...)
			if len(line) > limit {
				return "", errors.New("line too long")
			}
			return string(line), err
		}
		line = append(line, chunk...)
		break
	}
	if len(line) > limit {
		return "", errors.New("line too long")
	}
	return string(line), nil
}
