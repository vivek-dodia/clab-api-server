package api

import (
	"bufio"
	"net/http"
	"time"
)

const ndjsonStreamHeartbeatInterval = 25 * time.Second

func writeNDJSONHeartbeat(writer *bufio.Writer, flusher http.Flusher) bool {
	if err := writer.WriteByte('\n'); err != nil {
		return false
	}
	if err := writer.Flush(); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

func writeNDJSONLine(writer *bufio.Writer, flusher http.Flusher, line string) bool {
	if _, err := writer.WriteString(line); err != nil {
		return false
	}
	if err := writer.WriteByte('\n'); err != nil {
		return false
	}
	if err := writer.Flush(); err != nil {
		return false
	}
	flusher.Flush()
	return true
}
