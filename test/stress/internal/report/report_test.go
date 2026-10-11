package report

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadStepsAndStats(t *testing.T) {
	dir := t.TempDir()
	tsv := "gen\t100\t200\tok\t0\t0\t\tlimit=256Mi\nusers-256Mi\t200\t500\tok\t0\t5\tOOMKilled\tlimit=256Mi\n# comment\nbad line\n"
	if err := os.WriteFile(filepath.Join(dir, "steps.tsv"), []byte(tsv), 0o644); err != nil {
		t.Fatal(err)
	}
	steps, err := ReadSteps(filepath.Join(dir, "steps.tsv"))
	if err != nil || len(steps) != 2 {
		t.Fatalf("%v %v", steps, err)
	}
	u := steps[1]
	if u.Name != "users-256Mi" || u.RestartsEnd-u.RestartsStart != 5 || u.LastReason != "OOMKilled" || u.End.Sub(u.Start) != 300*time.Second {
		t.Errorf("%+v", u)
	}
	pts := []Point{{time.Unix(150, 0), 10}, {time.Unix(250, 0), 30}, {time.Unix(300, 0), 50}, {time.Unix(600, 0), 999}}
	s := StatOf(pts, u.Start, u.End)
	if s.N != 2 || s.Min != 30 || s.Max != 50 || s.Avg != 40 {
		t.Errorf("%+v", s)
	}
	sum := Sum([]SeriesData{{Points: pts[:2]}, {Points: pts[1:3]}})
	if len(sum) != 3 || sum[1].V != 60 {
		t.Errorf("%+v", sum)
	}
}
