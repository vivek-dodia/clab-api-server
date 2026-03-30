package api

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"
)

var lifecycleLogCaptureMu sync.Mutex
var lifecycleInfoWarnErrorPattern = regexp.MustCompile(`^(?:\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (INFO|WARN|ERRO|ERROR|FATAL|PANIC)\b`)
var lifecycleAnsiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

const lifecycleScannerMaxBytes = 1024 * 1024

type lifecycleStreamEvent struct {
	Type    string `json:"type"`
	Line    string `json:"line,omitempty"`
	Stream  string `json:"stream,omitempty"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

type lifecycleStreamOptions struct {
	Preamble  []string
	OnSuccess func() []string
}

func captureLifecycleLogs(run func() error) ([]string, error) {
	return captureLifecycleLogsWithSink(run, nil)
}

func captureLifecycleLogsWithSink(run func() error, onLine func(string)) ([]string, error) {
	lifecycleLogCaptureMu.Lock()
	defer lifecycleLogCaptureMu.Unlock()

	logReader, logWriter := io.Pipe()
	defer logReader.Close()

	linesCh := make(chan string, 256)
	scannerErrCh := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(logReader)
		scanner.Buffer(make([]byte, 0, 64*1024), lifecycleScannerMaxBytes)
		for scanner.Scan() {
			line := normalizeLifecycleLogLine(scanner.Text())
			if !shouldKeepLifecycleLogLine(line) {
				continue
			}
			if onLine != nil {
				onLine(line)
			}
			linesCh <- line
		}
		close(linesCh)
		scannerErrCh <- scanner.Err()
	}()

	log.SetOutput(io.MultiWriter(os.Stderr, logWriter))
	defer log.SetOutput(os.Stderr)

	runErr := run()
	_ = logWriter.Close()

	logs := make([]string, 0, 64)
	for line := range linesCh {
		logs = append(logs, line)
	}

	if scanErr := <-scannerErrCh; scanErr != nil && runErr == nil {
		runErr = scanErr
	}

	return logs, runErr
}

func streamLifecycleCommand(c *gin.Context, run func() error, successMessage string) {
	streamLifecycleCommandWithOptions(c, run, successMessage, nil)
}

func streamLifecycleCommandWithOptions(c *gin.Context, run func() error, successMessage string, opts *lifecycleStreamOptions) {
	c.Writer.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("X-Accel-Buffering", "no")

	c.Status(http.StatusOK)
	c.Writer.WriteHeaderNow()
	if flusher, ok := c.Writer.(http.Flusher); ok {
		flusher.Flush()
	}

	if opts != nil {
		for _, line := range opts.Preamble {
			normalized := normalizeLifecycleLogLine(line)
			if normalized == "" {
				continue
			}
			_ = writeLifecycleStreamEvent(c, lifecycleStreamEvent{
				Type:   "log",
				Line:   normalized,
				Stream: inferLifecycleLogStream(normalized),
			})
		}
	}

	_, runErr := captureLifecycleLogsWithSink(run, func(line string) {
		_ = writeLifecycleStreamEvent(c, lifecycleStreamEvent{
			Type:   "log",
			Line:   line,
			Stream: inferLifecycleLogStream(line),
		})
	})
	if runErr != nil {
		_ = writeLifecycleStreamEvent(c, lifecycleStreamEvent{
			Type:  "error",
			Error: runErr.Error(),
		})
		return
	}

	if opts != nil && opts.OnSuccess != nil {
		for _, line := range opts.OnSuccess() {
			normalized := normalizeLifecycleLogLine(line)
			if normalized == "" {
				continue
			}
			_ = writeLifecycleStreamEvent(c, lifecycleStreamEvent{
				Type:   "log",
				Line:   normalized,
				Stream: inferLifecycleLogStream(normalized),
			})
		}
	}

	_ = writeLifecycleStreamEvent(c, lifecycleStreamEvent{
		Type:    "done",
		Message: successMessage,
	})
}

func writeLifecycleStreamEvent(c *gin.Context, event lifecycleStreamEvent) bool {
	payload, err := json.Marshal(event)
	if err != nil {
		return false
	}
	if _, err := c.Writer.Write(append(payload, '\n')); err != nil {
		return false
	}
	if flusher, ok := c.Writer.(http.Flusher); ok {
		flusher.Flush()
	}
	return true
}

func inferLifecycleLogStream(line string) string {
	upper := strings.ToUpper(line)
	if strings.Contains(upper, " ERROR ") ||
		strings.Contains(upper, " FATAL ") ||
		strings.Contains(upper, "PANIC") ||
		strings.HasPrefix(upper, "STDERR:") {
		return "stderr"
	}
	return "stdout"
}

func shouldKeepLifecycleLogLine(line string) bool {
	trimmed := normalizeLifecycleLogLine(line)
	if trimmed == "" {
		return false
	}

	// Suppress API wrapper context lines; keep lifecycle output closer to native CLI.
	if strings.Contains(trimmed, " username=") {
		return false
	}

	// Keep the same high-signal output users see in VS Code lifecycle logs.
	if lifecycleInfoWarnErrorPattern.MatchString(trimmed) {
		return true
	}
	return strings.HasPrefix(trimmed, "notice=") ||
		strings.HasPrefix(trimmed, "│") ||
		strings.HasPrefix(trimmed, "╭") ||
		strings.HasPrefix(trimmed, "├") ||
		strings.HasPrefix(trimmed, "╰") ||
		strings.HasPrefix(trimmed, "🎉=") ||
		strings.HasPrefix(trimmed, "deprecated type=")
}

func normalizeLifecycleLogLine(line string) string {
	normalized := strings.TrimSpace(strings.TrimRight(line, "\r"))
	if normalized == "" {
		return ""
	}
	return strings.TrimSpace(lifecycleAnsiEscapePattern.ReplaceAllString(normalized, ""))
}
