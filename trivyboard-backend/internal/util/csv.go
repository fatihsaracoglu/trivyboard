package util

import (
	"fmt"
	"regexp"
	"strings"
)

var dangerousStart = regexp.MustCompile(`^[=+\-@\t\r]`)
var needsQuoting = regexp.MustCompile("[\",\n\r]")

// escapeCell escapes a single CSV cell value, guarding against spreadsheet
// formula injection and quoting cells that contain reserved characters.
func escapeCell(value interface{}) string {
	raw := ""
	if value != nil {
		raw = fmt.Sprintf("%v", value)
	}
	cell := raw
	if dangerousStart.MatchString(cell) {
		cell = "'" + cell
	}
	if needsQuoting.MatchString(cell) {
		cell = "\"" + strings.ReplaceAll(cell, "\"", "\"\"") + "\""
	}
	return cell
}

// ToCSV renders a header + rows matrix as a CSV string with CRLF line endings.
func ToCSV(header []string, rows [][]interface{}) string {
	parts := make([]string, 0, len(rows)+1)
	headerCells := make([]string, len(header))
	for i, h := range header {
		headerCells[i] = escapeCell(h)
	}
	parts = append(parts, strings.Join(headerCells, ","))
	for _, row := range rows {
		cells := make([]string, len(row))
		for i, c := range row {
			cells[i] = escapeCell(c)
		}
		parts = append(parts, strings.Join(cells, ","))
	}
	return strings.Join(parts, "\r\n") + "\r\n"
}
