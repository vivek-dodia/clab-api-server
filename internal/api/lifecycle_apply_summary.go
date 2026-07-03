package api

import (
	"fmt"
	"strings"

	"github.com/srl-labs/clab-api-server/internal/models"
)

type applySummaryRow struct {
	action string
	detail string
}

func buildApplySummaryTableLines(result models.ApplyLabResponse) []string {
	rows := collectApplySummaryRows(result)

	actionWidth := 18
	detailWidth := 48
	for _, row := range rows {
		if len(row.action)+2 > actionWidth {
			actionWidth = len(row.action) + 2
		}
		if len(row.detail)+2 > detailWidth {
			detailWidth = len(row.detail) + 2
		}
	}

	top := "╭" + strings.Repeat("─", actionWidth) + "┬" + strings.Repeat("─", detailWidth) + "╮"
	sep := "├" + strings.Repeat("─", actionWidth) + "┼" + strings.Repeat("─", detailWidth) + "┤"
	bottom := "╰" + strings.Repeat("─", actionWidth) + "┴" + strings.Repeat("─", detailWidth) + "╯"

	lines := []string{
		top,
		fmt.Sprintf("│%s│%s│", centerText("Action", actionWidth), centerText("Details", detailWidth)),
		sep,
	}
	for _, row := range rows {
		lines = append(lines, fmt.Sprintf(
			"│ %s│ %s│",
			padRight(truncate(row.action, actionWidth-2), actionWidth-1),
			padRight(truncate(row.detail, detailWidth-2), detailWidth-1),
		))
	}
	lines = append(lines, bottom)

	return lines
}

func collectApplySummaryRows(result models.ApplyLabResponse) []applySummaryRow {
	rows := make([]applySummaryRow, 0, 16)

	if result.DeployedLab {
		label := "deployed lab"
		if result.DryRun {
			label = "deploy lab"
		}
		rows = append(rows, applySummaryRow{action: label, detail: result.LabName})
	}

	appendRows := func(label string, values []string) {
		for _, value := range values {
			rows = append(rows, applySummaryRow{action: label, detail: value})
		}
	}

	appendRows("added nodes", result.AddedNodes)
	appendRows("deleted nodes", result.DeletedNodes)
	appendRows("recreated nodes", withApplyChangeReasons(result.RecreatedNodes, result.NodeChangeReasons))
	appendRows("started nodes", result.StartedNodes)
	appendRows("added links", result.AddedLinks)
	appendRows("deleted endpoints", result.DeletedEndpoints)
	appendRows("restarted nodes", withApplyChangeReasons(result.RestartedNodes, result.NodeChangeReasons))

	if len(rows) == 0 {
		rows = append(rows, applySummaryRow{action: "no changes", detail: "-"})
	}

	return rows
}

func withApplyChangeReasons(nodeNames []string, reasons map[string]string) []string {
	if len(reasons) == 0 {
		return nodeNames
	}

	values := make([]string, 0, len(nodeNames))
	for _, nodeName := range nodeNames {
		if reason, ok := reasons[nodeName]; ok && strings.TrimSpace(reason) != "" {
			values = append(values, fmt.Sprintf("%s (%s)", nodeName, reason))
			continue
		}
		values = append(values, nodeName)
	}

	return values
}
