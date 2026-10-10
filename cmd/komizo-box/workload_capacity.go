package main

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"time"
)

func workloadReportFresh(path string, now time.Time) error {
	body, err := os.ReadFile(path)
	if err != nil || len(body) > 1<<20 {
		return errors.New("capacity report unreadable or oversized")
	}
	var report struct {
		At time.Time `json:"at"`
	}
	if json.Unmarshal(body, &report) != nil || report.At.IsZero() || report.At.After(now) || now.Sub(report.At) > 2*time.Minute {
		return errors.New("capacity report must be from the last two minutes")
	}
	return nil
}
func runWorkloadCapacity(args []string) error {
	fs := flag.NewFlagSet("workload capacity", flag.ContinueOnError)
	report := fs.String("report", "", "root-owned capacity report")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *report == "" {
		return errors.New("capacity needs a report path")
	}
	return workloadReportFresh(*report, time.Now().UTC())
}
