package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/srl-labs/clab-api-server/internal/models"
)

func buildDeployPreambleLines() []string {
	version, _, _, ok := containerlabVersionDetails()
	if !ok || strings.TrimSpace(version) == "" {
		return nil
	}
	return []string{
		fmt.Sprintf("%s INFO Containerlab started version=%s", time.Now().Format("15:04:05"), version),
	}
}

func buildDeployVersionNoticeLines() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	message, err := buildContainerlabVersionCheckResult(ctx)
	if err != nil || !strings.Contains(message, "newer containerlab version") {
		return nil
	}

	message = strings.ReplaceAll(message, "sudo clab version upgrade", "clab version upgrade")
	lines := []string{fmt.Sprintf("%s INFO containerlab version", time.Now().Format("15:04:05")), "🎉="}
	for _, raw := range strings.Split(message, "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("│ %s", trimmed))
	}
	return lines
}

func buildDeploySummaryTableLines(labName string, inspectResult models.ClabInspectOutput) []string {
	containers, ok := inspectResult[labName]
	if !ok && len(inspectResult) == 1 {
		for _, entries := range inspectResult {
			containers = entries
			ok = true
		}
	}
	if !ok || len(containers) == 0 {
		return nil
	}

	sort.Slice(containers, func(i, j int) bool {
		return containers[i].Name < containers[j].Name
	})

	nameWidth := 20
	kindWidth := 43
	stateWidth := 9
	addrWidth := 19

	top := "╭" + strings.Repeat("─", nameWidth) + "┬" + strings.Repeat("─", kindWidth) + "┬" + strings.Repeat("─", stateWidth) + "┬" + strings.Repeat("─", addrWidth) + "╮"
	sep := "├" + strings.Repeat("─", nameWidth) + "┼" + strings.Repeat("─", kindWidth) + "┼" + strings.Repeat("─", stateWidth) + "┼" + strings.Repeat("─", addrWidth) + "┤"
	bottom := "╰" + strings.Repeat("─", nameWidth) + "┴" + strings.Repeat("─", kindWidth) + "┴" + strings.Repeat("─", stateWidth) + "┴" + strings.Repeat("─", addrWidth) + "╯"

	lines := []string{
		top,
		formatTableRow(
			centerText("Name", nameWidth),
			centerText("Kind/Image", kindWidth),
			centerText("State", stateWidth),
			centerText("IPv4/6 Address", addrWidth),
		),
		sep,
	}

	for idx, container := range containers {
		lines = append(lines, formatTableRow(
			padRight(truncate(container.Name, nameWidth), nameWidth),
			padRight(truncate(container.Kind, kindWidth), kindWidth),
			padRight(truncate(container.State, stateWidth), stateWidth),
			padRight(truncate(stripCIDR(container.IPv4Address), addrWidth), addrWidth),
		))
		lines = append(lines, formatTableRow(
			padRight("", nameWidth),
			padRight(truncate(container.Image, kindWidth), kindWidth),
			padRight("", stateWidth),
			padRight(truncate(stripCIDR(container.IPv6Address), addrWidth), addrWidth),
		))
		if idx < len(containers)-1 {
			lines = append(lines, sep)
		}
	}
	lines = append(lines, bottom)

	return lines
}

func formatTableRow(col1, col2, col3, col4 string) string {
	return fmt.Sprintf("│ %s │ %s │ %s │ %s │", col1, col2, col3, col4)
}

func padRight(value string, width int) string {
	if len(value) >= width {
		return value
	}
	return value + strings.Repeat(" ", width-len(value))
}

func centerText(value string, width int) string {
	if len(value) >= width {
		return value
	}
	left := (width - len(value)) / 2
	right := width - len(value) - left
	return strings.Repeat(" ", left) + value + strings.Repeat(" ", right)
}

func truncate(value string, width int) string {
	if width <= 0 || len(value) <= width {
		return value
	}
	if width <= 3 {
		return value[:width]
	}
	return value[:width-3] + "..."
}

func stripCIDR(value string) string {
	if idx := strings.Index(value, "/"); idx > 0 {
		return value[:idx]
	}
	return value
}
