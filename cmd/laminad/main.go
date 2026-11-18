package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"lamina/internal/engine"
	"lamina/internal/snapshot"
	"lamina/internal/transport"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		slog.Error("lamina stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	dir := flag.String("data", "var/lamina", "data directory exclusively owned by this process")
	addr := flag.String("listen", "127.0.0.1:7386", "HTTP bind address")
	restore := flag.String("restore", "", "validated backup to install into a new data directory before serving")
	verify := flag.String("verify", "", "precheck a backup image and print a report instead of serving")
	expectDigest := flag.String("expect-digest", "", "pin install to the payload SHA-256 observed during precheck")
	wantRead := flag.String("want-read", "", "precheck demand: relation@sequence that must remain readable")
	wantChange := flag.String("want-change", "", "precheck demand: change cursor (after sequence) that must be serviceable")
	wantJournal := flag.String("want-journal-id", "", "precheck demand: source journal id the image must carry")
	flag.Parse()

	if *verify != "" {
		if *restore != "" {
			return fmt.Errorf("-verify and -restore are mutually exclusive")
		}
		return runVerify(*verify, *wantRead, *wantChange, *wantJournal)
	}

	if *restore != "" {
		demandsNote := ""
		if *wantRead != "" || *wantChange != "" || *wantJournal != "" {
			demandsNote = " (demand flags only apply to -verify; run precheck before install)"
		}
		if err := engine.Restore(*dir, *restore, *expectDigest); err != nil {
			return fmt.Errorf("%w%s", err, demandsNote)
		}
	}
	db, err := engine.Open(*dir)
	if err != nil {
		return err
	}
	defer db.Close()
	server := &http.Server{Addr: *addr, Handler: transport.New(db), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 45 * time.Second, MaxHeaderBytes: 32 << 10}
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stopped)
	finished := make(chan error, 1)
	go func() { slog.Info("lamina ready", "address", *addr); finished <- server.ListenAndServe() }()
	select {
	case err = <-finished:
		if err != http.ErrServerClosed {
			return err
		}
	case <-stopped:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err = server.Shutdown(ctx); err != nil {
			server.Close()
			return err
		}
	}
	return nil
}

// runVerify performs a pure read-only precheck: one sequential read of the
// image, full validation and explicit demand verdicts. No data directory is
// created and no second copy of the database is expanded on disk.
func runVerify(path, wantRead, wantChange, wantJournal string) error {
	demands, err := buildDemands(wantRead, wantChange, wantJournal)
	if err != nil {
		return err
	}
	report, err := snapshot.Inspect(path, demands)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	os.Exit(report.ExitCode())
	return nil
}

func buildDemands(wantRead, wantChange, wantJournal string) ([]snapshot.Demand, error) {
	var demands []snapshot.Demand
	if wantRead != "" {
		relation, sequenceText, ok := strings.Cut(wantRead, "@")
		if !ok || relation == "" {
			return nil, fmt.Errorf("-want-read must look like relation@sequence")
		}
		sequence, err := strconv.ParseUint(sequenceText, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("-want-read sequence: %w", err)
		}
		demands = append(demands, snapshot.Demand{Kind: "read", Relation: relation, Sequence: sequence})
	}
	if wantChange != "" {
		sequence, err := strconv.ParseUint(wantChange, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("-want-change: %w", err)
		}
		demands = append(demands, snapshot.Demand{Kind: "change", Sequence: sequence})
	}
	if wantJournal != "" {
		demands = append(demands, snapshot.Demand{Kind: "journal_id", JournalID: wantJournal})
	}
	return demands, nil
}
