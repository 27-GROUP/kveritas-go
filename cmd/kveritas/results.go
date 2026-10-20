package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Mamadou2727/kveritas-go/internal/metrics"
	"github.com/Mamadou2727/kveritas-go/internal/runner"
	"github.com/Mamadou2727/kveritas-go/internal/session"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func resultsOptions(sess *session.Session) runner.Options {
	return runner.Options{Autolog: sess.Results == "autolog", FindAuto: sess.Results == ""}
}

func interactive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
}

// Asked once per session, the first time a run declares no results. A batch job is
// never stopped by a question: it gets the hint and keeps declared results only.
func chooseResults(kvDir string, sess *session.Session) string {
	return askResults(kvDir, sess, "No results declared in this run.")
}

func askResults(kvDir string, sess *session.Session, intro string) string {
	if !interactive() {
		fmt.Fprintln(os.Stderr, "[kveritas] "+intro)
		metrics.DeclareHint()
		fmt.Fprintln(os.Stderr, "[kveritas] Or detect them from output and metric files: kveritas autolog on")
		return ""
	}
	fmt.Fprint(os.Stderr, "[kveritas] "+intro+` How should results be captured?
  1  Declare them: print one line per result, e.g.  print("KV runtime_s=1.84")
  2  Autolog: find them in what your program prints or saves (may miss some)
  3  No results: record code, hardware and time only
Choice [1]: `)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	choice := "declared"
	switch strings.TrimSpace(line) {
	case "2":
		choice = "autolog"
	case "3":
		choice = "none"
	}
	sess.Results = choice
	if err := sess.Save(kvDir); err != nil {
		fmt.Fprintf(os.Stderr, "[kveritas] Warning: could not save the choice: %v\n", err)
	}
	switch choice {
	case "declared":
		metrics.DeclareHint()
	case "autolog":
		fmt.Fprintln(os.Stderr, "[kveritas] Autolog on for this session. Detected results are marked automatic in the report.")
	}
	return choice
}

var cmdAutolog = &cobra.Command{
	Use:   "autolog [on|off]",
	Short: "Find results in output and metric files when a run prints no KV lines",
	Long: `Autolog reads results from the output of common tools (Hugging Face, Keras,
Lightning, XGBoost, LightGBM, hyperfine, Google Benchmark, criterion, time) and from
metric files a run writes (TensorBoard, trainer_state.json, CSV logs, MLflow). It is
best effort, and every detected value is marked automatic in the report. Results a
program prints as KV lines always take precedence.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		kvDir, err := session.Find()
		if err != nil {
			return err
		}
		sess, err := session.Load(kvDir)
		if err != nil {
			return err
		}
		if len(args) == 0 {
			state := "off"
			if sess.Results == "autolog" {
				state = "on"
			}
			fmt.Printf("Autolog: %s\n", state)
			return nil
		}
		switch args[0] {
		case "on":
			sess.Results = "autolog"
		case "off":
			sess.Results = "declared"
		default:
			return fmt.Errorf("expected on or off")
		}
		if err := sess.Save(kvDir); err != nil {
			return err
		}
		fmt.Printf("Autolog: %s\n", args[0])
		return nil
	},
}
