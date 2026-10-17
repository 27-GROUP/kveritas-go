package main

import (
	"encoding/json"
	"fmt"
	"io"
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
	observePID        int
	observeChannel    string
	observeLive       bool
	observeStdout     string
	observeStderr     string
	observeEchoStdout string
	observeEchoStderr string
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
	channel, err := fdFile(observeChannel, "kveritas-channel")
	if err != nil || channel == nil {
		return res, fmt.Errorf("--channel: %v", err)
	}
	att := &runner.Attachment{PID: observePID, Channel: channel}
	for _, f := range []struct {
		spec string
		dst  **os.File
	}{{observeStdout, &att.Stdout}, {observeStderr, &att.Stderr}} {
		if *f.dst, err = fdFile(f.spec, "kveritas-output"); err != nil {
			return res, err
		}
	}
	for _, f := range []struct {
		spec string
		dst  *io.Writer
	}{{observeEchoStdout, &att.Echo}, {observeEchoStderr, &att.EchoErr}} {
		w, err := fdFile(f.spec, "kveritas-echo")
		if err != nil {
			return res, err
		}
		if w != nil {
			*f.dst = w
		}
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

// An empty spec means the descriptor was not passed.
func fdFile(spec, name string) (*os.File, error) {
	if spec == "" {
		return nil, nil
	}
	text, ok := strings.CutPrefix(spec, "fd:")
	fd, err := strconv.Atoi(text)
	if !ok || err != nil || fd < 3 {
		return nil, fmt.Errorf("invalid descriptor %q, expected fd:<n>", spec)
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		return nil, fmt.Errorf("descriptor %d is not open", fd)
	}
	return f, nil
}

func init() {
	cmdObserve.Flags().IntVar(&observePID, "pid", 0, "process to observe")
	cmdObserve.Flags().StringVar(&observeStdout, "stdout", "", "read end of the observed process's redirected stdout, fd:<n>")
	cmdObserve.Flags().StringVar(&observeStderr, "stderr", "", "read end of the observed process's redirected stderr, fd:<n>")
	cmdObserve.Flags().StringVar(&observeEchoStdout, "echo-stdout", "", "where to pass captured stdout on, fd:<n>")
	cmdObserve.Flags().StringVar(&observeEchoStderr, "echo-stderr", "", "where to pass captured stderr on, fd:<n>")
	cmdObserve.Flags().StringVar(&observeChannel, "channel", "", "result channel, fd:<n>")
	cmdObserve.Flags().BoolVar(&observeLive, "live", false, "stream hardware samples to stdout while observing")
	_ = cmdObserve.MarkFlagRequired("pid")
	_ = cmdObserve.MarkFlagRequired("channel")
}
