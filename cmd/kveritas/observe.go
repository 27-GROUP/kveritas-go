package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/anchor"
	"github.com/Mamadou2727/kveritas-go/internal/client"
	"github.com/Mamadou2727/kveritas-go/internal/runner"
	"github.com/Mamadou2727/kveritas-go/internal/session"
	"github.com/spf13/cobra"
)

var (
	observePID     int
	observeChannel string
	observeLive    bool
)

type observeResult struct {
	Kind     string `json:"kind"`
	RunID    string `json:"run_id,omitempty"`
	Recorded bool   `json:"recorded"`
	ExitCode int    `json:"exit_code"`
	Metrics  int    `json:"metrics"`
	Claims   int    `json:"claims"`
	Phases   int    `json:"phases"`
	Seeds    int    `json:"seeds"`
	Error    string `json:"error,omitempty"`
}

// Used by the SDK: the observer joins a running process (its own interpreter, a
// notebook kernel) and reads results from a pipe the SDK passes in.
var cmdObserve = &cobra.Command{
	Use:    "observe --pid <pid> --channel fd:<n>",
	Short:  "Observe an already running process (used by the SDKs)",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := observe()
		if err != nil {
			res.Error = err.Error()
		}
		data, _ := json.Marshal(res)
		fmt.Println(string(data))
		return err
	},
}

func observe() (observeResult, error) {
	res := observeResult{Kind: "result"}
	fdText, ok := strings.CutPrefix(observeChannel, "fd:")
	if !ok {
		return res, fmt.Errorf("--channel must be fd:<n>")
	}
	fd, err := strconv.Atoi(fdText)
	if err != nil || fd < 3 {
		return res, fmt.Errorf("invalid channel descriptor %q", observeChannel)
	}
	channel := os.NewFile(uintptr(fd), "kveritas-channel")
	if channel == nil {
		return res, fmt.Errorf("channel descriptor %d is not open", fd)
	}

	kvDir, err := session.Find()
	if err != nil {
		return res, err
	}
	sess, err := session.Load(kvDir)
	if err != nil {
		return res, err
	}
	if sess.Sealed {
		return res, fmt.Errorf("session is already sealed; cannot add more runs")
	}
	release, err := anchor.AcquireRun(kvDir)
	if err != nil {
		return res, err
	}
	defer release()
	if err := recoverInterrupted(kvDir, sess); err != nil {
		return res, err
	}
	online := sess.ServerURL != "local"
	var c *client.Client
	if online {
		c = client.New(sess.ServerURL)
		_, _ = anchor.Flush(c, kvDir)
		stop := anchor.Background(c, kvDir, 30*time.Second)
		defer stop()
	}

	att := &runner.Attachment{PID: observePID, Channel: channel}
	if observeLive {
		att.Live = os.Stdout
	}
	inv := sess.Invocations
	if err := anchor.BeginRun(kvDir, anchor.Inflight{Invocation: inv, Index: len(sess.Runs),
		Command: []string{"attached", strconv.Itoa(observePID)}, StartedAt: time.Now().UTC()}); err != nil {
		return res, err
	}
	rec, err := runner.Attach(sess, att)
	if err != nil {
		anchor.EndRun(kvDir)
		return res, err
	}
	if err := anchorInvocation(kvDir, sess, rec, inv); err != nil {
		return res, err
	}
	if online {
		if left, ferr := anchor.FlushWithin(c, kvDir, 30*time.Second); left > 0 {
			fmt.Fprintf(os.Stderr, "[kveritas] Run anchor queued and will be retried (%v)\n", ferr)
		}
	}

	res.RunID, res.ExitCode = rec.ID, rec.ExitCode
	res.Metrics, res.Claims, res.Phases, res.Seeds = len(rec.Metrics), len(rec.Claims), len(rec.Phases), len(rec.Seeds)
	if rec.ExitCode != 0 {
		return res, nil
	}
	if err := sess.SaveRun(kvDir, rec); err != nil {
		return res, err
	}
	sess.Runs = append(sess.Runs, rec.ID)
	if err := sess.Save(kvDir); err != nil {
		return res, err
	}
	res.Recorded = true
	return res, nil
}

func init() {
	cmdObserve.Flags().IntVar(&observePID, "pid", 0, "process to observe")
	cmdObserve.Flags().StringVar(&observeChannel, "channel", "", "result channel, fd:<n>")
	cmdObserve.Flags().BoolVar(&observeLive, "live", false, "stream hardware samples to stdout while observing")
	_ = cmdObserve.MarkFlagRequired("pid")
	_ = cmdObserve.MarkFlagRequired("channel")
}
