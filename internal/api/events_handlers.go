// internal/api/events_handlers.go
package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
)

const (
	eventsScannerMaxBytes   = 1024 * 1024
	labOwnershipCacheTTL    = 15 * time.Second
	labOwnershipLookupLimit = 10 * time.Second
)

type labOwnershipEntry struct {
	owner     string
	expiresAt time.Time
}

type clabEventJSON struct {
	Attributes map[string]string `json:"attributes"`
}

// @Summary Stream Containerlab Events
// @Description Streams containerlab events. The response stays open until the client disconnects.
// @Tags Events
// @Security BearerAuth
// @Produce plain,json,octet-stream
// @Param format query string false "Output format ('plain' or 'json'). Default is 'plain'." example="plain"
// @Param initialState query boolean false "Include initial snapshot events when the stream starts." example="false"
// @Param interfaceStats query boolean false "Include interface stats events." example="false"
// @Param interfaceStatsInterval query string false "Interval for interface stats collection (e.g., 10s). Requires interfaceStats=true." example="10s"
// @Success 200 {string} string "Event stream (plain or JSON lines)"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/events [get]
func StreamEventsHandler(c *gin.Context) {
	username := c.GetString("username")
	isSuperuserUser := isSuperuser(username)

	format := strings.ToLower(c.DefaultQuery("format", "plain"))
	if format != "plain" && format != "json" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid format parameter. Use 'plain' or 'json'."})
		return
	}

	initialState, err := parseBoolQuery(c, "initialState", false)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid initialState parameter. Use true or false."})
		return
	}

	interfaceStats, err := parseBoolQuery(c, "interfaceStats", false)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid interfaceStats parameter. Use true or false."})
		return
	}

	interfaceStatsInterval := c.Query("interfaceStatsInterval")
	if interfaceStatsInterval != "" && !isValidDurationString(interfaceStatsInterval) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid interfaceStatsInterval parameter. Use a valid duration like 10s."})
		return
	}
	if interfaceStatsInterval != "" && !interfaceStats {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "interfaceStatsInterval requires interfaceStats=true."})
		return
	}

	args := []string{}
	if runtime := strings.TrimSpace(config.AppConfig.ClabRuntime); runtime != "" {
		args = append(args, "--runtime", runtime)
	}
	args = append(args, "events", "--format", format)
	if initialState {
		args = append(args, "--initial-state")
	}
	if interfaceStats {
		args = append(args, "--interface-stats")
	}
	if interfaceStatsInterval != "" {
		args = append(args, "--interface-stats-interval", interfaceStatsInterval)
	}

	log.Infof("StreamEvents user '%s': Starting containerlab events stream (format=%s, initialState=%v, interfaceStats=%v, interval=%s)",
		username, format, initialState, interfaceStats, interfaceStatsInterval)

	if format == "json" {
		c.Writer.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	} else {
		c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
	c.Writer.Header().Set("Cache-Control", "no-cache")

	ctx, cancel := context.WithCancel(c.Request.Context())
	defer cancel()

	notifyChan := c.Writer.CloseNotify()
	go func() {
		<-notifyChan
		log.Infof("StreamEvents user '%s': Client disconnected", username)
		cancel()
	}()

	cmd := exec.CommandContext(ctx, "containerlab", args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Errorf("StreamEvents user '%s': Failed to create stdout pipe: %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to create stdout pipe: %s", err.Error())})
		return
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Errorf("StreamEvents user '%s': Failed to create stderr pipe: %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to create stderr pipe: %s", err.Error())})
		return
	}

	if err := cmd.Start(); err != nil {
		log.Errorf("StreamEvents user '%s': Failed to start containerlab events: %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to start containerlab events: %s", err.Error())})
		return
	}

	// Ensure the client receives headers immediately, even if no events arrive yet.
	c.Status(http.StatusOK)
	c.Writer.WriteHeaderNow()
	if flusher, ok := c.Writer.(http.Flusher); ok {
		flusher.Flush()
	}

	var stderrOutput strings.Builder
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			stderrOutput.WriteString(scanner.Text() + "\n")
		}
	}()

	ownershipCache := make(map[string]labOwnershipEntry)
	allowedLab := func(lab string) bool {
		if isSuperuserUser {
			return true
		}
		if lab == "" {
			return false
		}
		now := time.Now()
		if entry, ok := ownershipCache[lab]; ok && now.Before(entry.expiresAt) {
			return entry.owner == username
		}
		ctx, cancel := context.WithTimeout(context.Background(), labOwnershipLookupLimit)
		defer cancel()
		info, exists, lookupErr := getLabInfo(ctx, username, lab)
		owner := ""
		if lookupErr == nil && exists && info != nil {
			owner = info.Owner
		}
		ownershipCache[lab] = labOwnershipEntry{
			owner:     owner,
			expiresAt: now.Add(labOwnershipCacheTTL),
		}
		return owner == username
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), eventsScannerMaxBytes)

	c.Stream(func(w io.Writer) bool {
		for scanner.Scan() {
			line := scanner.Text()
			if !isSuperuserUser {
				labName, ok := extractLabFromEventLine(line, format)
				if !ok || !allowedLab(labName) {
					continue
				}
			}
			if _, err := io.WriteString(w, line+"\n"); err != nil {
				return false
			}
			return true
		}
		return false
	})

	wg.Wait()

	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			// Client disconnected or context canceled; no action needed.
		} else {
			log.Warnf("StreamEvents user '%s': Command ended with error: %v. Stderr: %s", username, err, stderrOutput.String())
		}
	}

	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		log.Errorf("StreamEvents user '%s': Scanner error: %v", username, err)
	}
}

func parseBoolQuery(c *gin.Context, name string, defaultValue bool) (bool, error) {
	raw := c.Query(name)
	if raw == "" {
		return defaultValue, nil
	}
	return strconv.ParseBool(raw)
}

func extractLabFromEventLine(line, format string) (string, bool) {
	if format == "json" {
		return extractLabFromJSONLine(line)
	}
	return extractLabFromPlainLine(line)
}

func extractLabFromJSONLine(line string) (string, bool) {
	var evt clabEventJSON
	if err := json.Unmarshal([]byte(line), &evt); err != nil {
		return "", false
	}
	if evt.Attributes == nil {
		return "", false
	}
	if lab := evt.Attributes["lab"]; lab != "" {
		return lab, true
	}
	if lab := evt.Attributes["containerlab"]; lab != "" {
		return lab, true
	}
	return "", false
}

func extractLabFromPlainLine(line string) (string, bool) {
	start := strings.LastIndex(line, "(")
	end := strings.LastIndex(line, ")")
	if start == -1 || end == -1 || end <= start {
		return "", false
	}
	attrs := line[start+1 : end]
	parts := strings.Split(attrs, ", ")
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := kv[0]
		value := kv[1]
		if key == "lab" || key == "containerlab" {
			return value, true
		}
	}
	return "", false
}
