// Package history persists reports as gzipped JSON and loads recent ones,
// mirroring main.py's _save_report/_apply_retention/load_historical_data.
package history

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

// Save writes the report as report-<unixnano>.json.gz and applies retention.
func Save(r *types.SystemReport, dir string, maxFiles int) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	name := fmt.Sprintf("report-%d.json.gz", time.Now().UTC().UnixNano())
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	if err := json.NewEncoder(gz).Encode(r); err != nil {
		return err
	}
	applyRetention(dir, maxFiles)
	return nil
}

func listReportFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".gz") {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	// Newest first by modification time.
	sort.Slice(files, func(i, j int) bool {
		fi, _ := os.Stat(files[i])
		fj, _ := os.Stat(files[j])
		if fi == nil || fj == nil {
			return false
		}
		return fi.ModTime().After(fj.ModTime())
	})
	return files
}

func applyRetention(dir string, maxFiles int) {
	if maxFiles <= 0 {
		return
	}
	files := listReportFiles(dir)
	for _, f := range files[min(len(files), maxFiles):] {
		_ = os.Remove(f)
	}
}

// Load reads up to n most-recent reports (newest first). Tolerates one report
// per gzipped file, or gzipped JSON-lines (last valid object wins per file).
func Load(dir string, n int) []*types.SystemReport {
	files := listReportFiles(dir)
	if n > 0 && len(files) > n {
		files = files[:n]
	}
	var reports []*types.SystemReport
	for _, path := range files {
		if r := readReport(path); r != nil {
			reports = append(reports, r)
		}
	}
	return reports
}

func readReport(path string) *types.SystemReport {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil
	}
	defer gz.Close()
	dec := json.NewDecoder(gz)
	var last *types.SystemReport
	for {
		var r types.SystemReport
		if err := dec.Decode(&r); err != nil {
			break
		}
		rr := r
		last = &rr
	}
	return last
}
