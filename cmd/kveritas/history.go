package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/anchor"
	"github.com/Mamadou2727/kveritas-go/internal/client"
	"github.com/Mamadou2727/kveritas-go/internal/crypto"
	"github.com/Mamadou2727/kveritas-go/internal/provenance"
	"github.com/Mamadou2727/kveritas-go/internal/session"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var branchName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$`)

// Inside a kveritas shell the shell holds the run lock and is idle while one of these
// commands runs, so they act under its lock instead of taking their own.
func historySession(create bool) (string, *session.Session, func(), error) {
	kvDir, err := session.Find()
	if err != nil {
		if !create {
			return "", nil, nil, fmt.Errorf("no session here; start one with kveritas run, shell or init")
		}
		if err := cmdInit.RunE(cmdInit, nil); err != nil {
			return "", nil, nil, err
		}
		if kvDir, err = session.Find(); err != nil {
			return "", nil, nil, err
		}
	}
	sess, err := session.Load(kvDir)
	if err != nil {
		return "", nil, nil, err
	}
	if sess.Sealed {
		return "", nil, nil, fmt.Errorf("session is already sealed")
	}
	if sess.Type == "harness" {
		return "", nil, nil, fmt.Errorf("this is an agent session; history steps are for experiment runs")
	}
	release := func() {}
	pid, held := anchor.RunLockHolder(kvDir)
	if shell := os.Getenv("KVERITAS_SHELL"); held && shell == strconv.Itoa(pid) {
		if _, running := anchor.LoadInflight(kvDir); running {
			return "", nil, nil, fmt.Errorf("a command is still running in this shell")
		}
	} else {
		if release, err = anchor.AcquireRun(kvDir); err != nil {
			return "", nil, nil, err
		}
		if err := recoverInterrupted(kvDir, sess); err != nil {
			release()
			return "", nil, nil, err
		}
	}
	return kvDir, sess, release, nil
}

func stepDigest(st session.Step) (string, error) {
	st.Digest = ""
	return crypto.CanonicalHash(st)
}

func addStep(kvDir string, sess *session.Session, st session.Step) (*session.Step, error) {
	st.ID = uuid.New().String()[:8]
	st.At = time.Now().UTC()
	if st.Branch == "" {
		st.Branch = sess.CurrentBranch()
	}
	st.Invocation = sess.Invocations
	digest, err := stepDigest(st)
	if err != nil {
		return nil, err
	}
	st.Digest = digest
	prev := sess.ChainHead
	if prev == "" {
		prev = anchor.Genesis(sess.ID)
	}
	chain := anchor.Next(prev, digest)
	online := sess.ServerURL != "local"
	if online {
		if err := anchor.Enqueue(kvDir, client.NewStepAnchor(sess, &st, chain)); err != nil {
			return nil, err
		}
	}
	sess.Invocations = st.Invocation + 1
	sess.ChainHead = chain
	sess.Steps = append(sess.Steps, st)
	if err := sess.Save(kvDir); err != nil {
		return nil, err
	}
	if online {
		if left, ferr := anchor.Flush(client.New(sess.ServerURL), kvDir); left > 0 {
			if anchor.Rejected(ferr) {
				fmt.Fprintf(os.Stderr, "[kveritas] Warning: the server rejected this step: %v\n", ferr)
			} else {
				fmt.Fprintln(os.Stderr, "[kveritas] Offline: step saved and will reach the server later")
			}
		}
	}
	return &sess.Steps[len(sess.Steps)-1], nil
}

func findStep(sess *session.Session, kind, ref string) (*session.Step, error) {
	var hit *session.Step
	for i := range sess.Steps {
		st := &sess.Steps[i]
		if st.Kind == kind && ref != "" && strings.HasPrefix(st.ID, ref) {
			if hit != nil && hit.ID != st.ID {
				return nil, fmt.Errorf("%q matches more than one %s", ref, kind)
			}
			hit = st
		}
	}
	if hit == nil {
		return nil, fmt.Errorf("no %s %q; see kveritas log", kind, ref)
	}
	return hit, nil
}

func baseCheckpoint(sess *session.Session) *session.Step {
	var base *session.Step
	for i := range sess.Steps {
		switch st := &sess.Steps[i]; st.Kind {
		case "checkpoint":
			base = st
		case "restore":
			if t, err := findStep(sess, "checkpoint", st.Target); err == nil {
				base = t
			}
		}
	}
	return base
}

func checkpointLabel(st *session.Step) string {
	if st.Message == "" {
		return st.ID
	}
	return fmt.Sprintf("%s %q", st.ID, st.Message)
}

func saveCheckpoint(kvDir string, sess *session.Session, message string, files []string) (*session.Step, error) {
	m, err := provenance.Capture(sess.ProjectDir, kvDir, files)
	if err != nil {
		return nil, err
	}
	st, err := addStep(kvDir, sess, session.Step{Kind: "checkpoint", Message: message,
		Root: m.Root([]byte(sess.ProvSalt)), Files: len(m.Files)})
	if err != nil {
		return nil, err
	}
	return st, provenance.SaveManifest(kvDir, st.ID, m)
}

var (
	checkpointMsg   string
	checkpointFiles []string
)

var cmdCheckpoint = &cobra.Command{
	Use:   "checkpoint [-m message] [--files f1,f2]",
	Short: "Save the project's files as a point you can come back to",
	Long: `Saves a copy of the project's code and config files, plus any files named with
--files (a model checkpoint, a dataset split), so kveritas restore can bring them
back. The copy stays on this machine. The server receives a salted fingerprint,
anchored in the same chain as your runs, so a checkpoint cannot be removed later.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		kvDir, sess, release, err := historySession(true)
		if err != nil {
			return err
		}
		defer release()
		st, err := saveCheckpoint(kvDir, sess, checkpointMsg, checkpointFiles)
		if err != nil {
			return err
		}
		fmt.Printf("Checkpoint %s saved (%s, branch %s)\n", checkpointLabel(st), files(st.Files), st.Branch)
		return nil
	},
}

var cmdRestore = &cobra.Command{
	Use:   "restore <checkpoint>",
	Short: "Put the project's files back as they were at a checkpoint",
	Long: `Writes back every saved file that changed since the checkpoint. Files created
since are left alone. Unsaved changes are first kept in an automatic checkpoint, so
nothing is lost. Nothing is removed from the history: the runs in between stay on
record, and the restore itself is anchored as a new step.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		kvDir, sess, release, err := historySession(false)
		if err != nil {
			return err
		}
		defer release()
		target, err := findStep(sess, "checkpoint", args[0])
		if err != nil {
			return err
		}
		m, err := provenance.LoadManifest(kvDir, target.ID)
		if err != nil {
			return err
		}
		drift := provenance.Compare(sess.ProjectDir, m)
		if len(drift.Modified)+len(drift.Deleted) == 0 {
			fmt.Printf("Files already match checkpoint %s\n", checkpointLabel(target))
			return nil
		}
		extra := m.Extra
		base := baseCheckpoint(sess)
		saved := false
		if base != nil {
			if bm, err := provenance.LoadManifest(kvDir, base.ID); err == nil {
				saved = provenance.Compare(sess.ProjectDir, bm).Clean()
				extra = append(extra, bm.Extra...)
			}
		}
		if !saved {
			var keep []string
			for _, f := range extra {
				if _, err := os.Stat(filepath.Join(sess.ProjectDir, filepath.FromSlash(f))); err == nil {
					keep = append(keep, f)
				}
			}
			auto, err := saveCheckpoint(kvDir, sess, "before restoring "+target.ID, keep)
			if err != nil {
				return fmt.Errorf("could not keep your current files: %w", err)
			}
			fmt.Printf("Current files kept as checkpoint %s\n", auto.ID)
		}
		n, err := provenance.Restore(sess.ProjectDir, kvDir, m)
		if err != nil {
			return err
		}
		if _, err := addStep(kvDir, sess, session.Step{Kind: "restore", Target: target.ID, Root: target.Root, Files: n}); err != nil {
			return err
		}
		fmt.Printf("Restored %s from checkpoint %s\n", files(n), checkpointLabel(target))
		for _, f := range drift.Added {
			fmt.Printf("  kept (new since the checkpoint): %s\n", f)
		}
		return nil
	},
}

func branches(sess *session.Session, runs []*session.RunRecord) []string {
	seen := map[string]bool{"main": true}
	out := []string{"main"}
	add := func(b string) {
		if b != "" && !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	for _, st := range sess.Steps {
		add(st.Branch)
	}
	for _, r := range runs {
		add(r.Branch)
	}
	return out
}

func loadRuns(kvDir string, sess *session.Session) []*session.RunRecord {
	var runs []*session.RunRecord
	for _, id := range sess.Runs {
		if r, err := session.LoadRun(kvDir, id); err == nil {
			runs = append(runs, r)
		}
	}
	return runs
}

var cmdBranch = &cobra.Command{
	Use:   "branch [name]",
	Short: "List branches, or start or switch to one",
	Long: `A branch is a label for the runs that follow, so experiments stay apart from
your main line. Files are not changed; use kveritas restore to start a branch from a
checkpoint. The report puts the current branch first and lists the others.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			kvDir, err := session.Find()
			if err != nil {
				return err
			}
			sess, err := session.Load(kvDir)
			if err != nil {
				return err
			}
			runs := loadRuns(kvDir, sess)
			for _, b := range branches(sess, runs) {
				n := 0
				for _, r := range runs {
					if session.RunBranch(r) == b {
						n++
					}
				}
				mark := " "
				if b == sess.CurrentBranch() {
					mark = "*"
				}
				fmt.Printf("%s %-20s %d run(s)\n", mark, b, n)
			}
			return nil
		}
		name := args[0]
		if !branchName.MatchString(name) {
			return fmt.Errorf("branch names use letters, digits, '.', '_' or '-' (up to 40)")
		}
		kvDir, sess, release, err := historySession(false)
		if err != nil {
			return err
		}
		defer release()
		from := sess.CurrentBranch()
		if name == from {
			fmt.Printf("Already on %s\n", name)
			return nil
		}
		kind := "branch"
		for _, b := range branches(sess, loadRuns(kvDir, sess)) {
			if b == name {
				kind = "switch"
			}
		}
		sess.Branch = name
		if name == "main" {
			sess.Branch = ""
		}
		if _, err := addStep(kvDir, sess, session.Step{Kind: kind, Branch: name, Target: from}); err != nil {
			return err
		}
		if kind == "branch" {
			fmt.Printf("Started branch %s from %s\n", name, from)
		} else {
			fmt.Printf("Switched to %s\n", name)
		}
		return nil
	},
}

var (
	asideMsg  string
	asideUndo bool
)

var cmdSetAside = &cobra.Command{
	Use:   "set-aside <run> [-m reason]",
	Short: "Move a run out of the main results, keeping it in the report",
	Long: `A set-aside run leaves the report's main results and is listed with its reason
in a separate section. It stays signed and counted, and the step is anchored, so
an auditor sees exactly what was set aside. --undo brings it back.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		kvDir, sess, release, err := historySession(false)
		if err != nil {
			return err
		}
		defer release()
		id := ""
		for _, r := range sess.Runs {
			if strings.HasPrefix(r, args[0]) {
				if id != "" {
					return fmt.Errorf("%q matches more than one run", args[0])
				}
				id = r
			}
		}
		if id == "" {
			return fmt.Errorf("no kept run %q; see kveritas log (failed runs are never in the main results)", args[0])
		}
		_, aside := sess.SetAside()[id]
		kind := "set-aside"
		switch {
		case asideUndo && !aside:
			return fmt.Errorf("run %s is not set aside", id)
		case asideUndo:
			kind = "bring-back"
		case aside:
			return fmt.Errorf("run %s is already set aside", id)
		}
		if _, err := addStep(kvDir, sess, session.Step{Kind: kind, Target: id, Message: asideMsg}); err != nil {
			return err
		}
		if asideUndo {
			fmt.Printf("Run %s is back in the main results\n", id)
		} else {
			fmt.Printf("Run %s set aside; it stays in the report, apart from the main results\n", id)
		}
		return nil
	},
}

type logNode struct {
	branch string
	glyph  string
	text   string
	detail []string
}

func runSummary(r *session.RunRecord, all bool) string {
	last := map[string]session.Metric{}
	var names []string
	for _, m := range r.Metrics {
		if m.Source == "measured" {
			continue
		}
		if _, ok := last[m.Name]; !ok {
			names = append(names, m.Name)
		}
		last[m.Name] = m
	}
	if !all && len(names) > 3 {
		names = append(names[:3], fmt.Sprintf("+%d", len(names)-3))
	}
	parts := make([]string, 0, len(names))
	for _, n := range names {
		if m, ok := last[n]; ok {
			parts = append(parts, fmt.Sprintf("%s=%.4g", n, m.Value))
		} else {
			parts = append(parts, n)
		}
	}
	return strings.Join(parts, " ")
}

func logNodes(sess *session.Session, runs []*session.RunRecord, verbose bool) []logNode {
	byInv := map[int]logNode{}
	aside := sess.SetAside()
	for _, r := range runs {
		text := fmt.Sprintf("%s  run         %s  %s  %s", r.ID, strings.Join(r.Command, " "), r.DurationFmt, runSummary(r, false))
		if why, ok := aside[r.ID]; ok {
			text += "  (set aside"
			if why != "" {
				text += ": " + why
			}
			text += ")"
		}
		n := logNode{branch: session.RunBranch(r), glyph: "o", text: strings.TrimRight(text, " ")}
		if verbose {
			if s := runSummary(r, true); s != "" {
				n.detail = append(n.detail, "results: "+s)
			}
			if p := r.Provenance; p != nil && len(p.Commits) > 0 {
				for _, c := range p.Commits[len(p.Commits)-1].Changed {
					n.detail = append(n.detail, c.Op+" "+c.Path)
				}
			}
		}
		byInv[r.Invocation] = n
	}
	for _, f := range sess.Failed {
		what := fmt.Sprintf("failed (exit %d)", f.ExitCode)
		if f.ExitCode == -1 {
			what = "interrupted"
		}
		b := f.Branch
		if b == "" {
			b = "main"
		}
		byInv[f.Invocation] = logNode{branch: b, glyph: "x", text: fmt.Sprintf("#%-7d run         %s  %s", f.Invocation+1, strings.Join(f.Command, " "), what)}
	}
	for _, st := range sess.Steps {
		var text string
		switch st.Kind {
		case "checkpoint":
			text = fmt.Sprintf("checkpoint  %q  %s", st.Message, files(st.Files))
		case "restore":
			text = fmt.Sprintf("restore     to %s, %s written", st.Target, files(st.Files))
		case "branch":
			text = fmt.Sprintf("branch      %s, from %s", st.Branch, st.Target)
		case "switch":
			text = fmt.Sprintf("switch      to %s", st.Branch)
		case "set-aside":
			text = "set aside   run " + st.Target
			if st.Message != "" {
				text += ": " + st.Message
			}
		case "bring-back":
			text = "bring back  run " + st.Target
		}
		byInv[st.Invocation] = logNode{branch: st.Branch, glyph: "o", text: st.ID + "  " + text}
	}
	nodes := make([]logNode, 0, sess.Invocations)
	for k := 0; k < sess.Invocations; k++ {
		n, ok := byInv[k]
		if !ok {
			n = logNode{branch: "main", glyph: "x", text: fmt.Sprintf("#%-7d run         failed or interrupted", k+1)}
		}
		nodes = append(nodes, n)
	}
	for i := len(nodes) - 1; i >= 0; i-- {
		if nodes[i].branch == sess.CurrentBranch() && nodes[i].glyph == "o" {
			nodes[i].glyph = "@"
			break
		}
	}
	return nodes
}

// Newest first, one column per branch, each branch joined to the one it started from.
func renderLog(sess *session.Session, nodes []logNode) {
	col := map[string]int{"main": 0}
	order := []string{"main"}
	parent := map[string]string{}
	forkAt := map[string]int{}
	for i, n := range nodes {
		if _, ok := col[n.branch]; !ok {
			col[n.branch] = len(order)
			order = append(order, n.branch)
		}
		if _, ok := forkAt[n.branch]; !ok && n.branch != "main" {
			forkAt[n.branch] = i
		}
	}
	for _, st := range sess.Steps {
		if st.Kind == "branch" {
			parent[st.Branch] = st.Target
		}
	}
	oldest := map[string]int{}
	newest := map[string]int{}
	for i, n := range nodes {
		if _, ok := oldest[n.branch]; !ok {
			oldest[n.branch] = i
		}
		newest[n.branch] = i
	}
	for b, i := range forkAt {
		p := parent[b]
		if p == "" {
			p = "main"
		}
		parent[b] = p
		if _, ok := newest[p]; !ok {
			oldest[p] = i
		}
		if newest[p] < i {
			newest[p] = i
		}
	}
	// A line passes between row i and row i-1 when the branch has nodes on both sides.
	below := func(b string, i int) bool {
		o, ok := oldest[b]
		return ok && o <= i-1 && i <= newest[b]
	}
	pad := func(s string) string { return s + strings.Repeat(" ", 2*len(order)+1-len([]rune(s))) }
	for i := len(nodes) - 1; i >= 0; i-- {
		n := nodes[i]
		var row, gap strings.Builder
		for _, b := range order {
			o, ok := oldest[b]
			switch {
			case b == n.branch:
				row.WriteString(n.glyph + " ")
			case ok && o < i && i < newest[b]:
				row.WriteString("│ ")
			default:
				row.WriteString("  ")
			}
			if below(b, i) {
				gap.WriteString("│ ")
			} else {
				gap.WriteString("  ")
			}
		}
		fmt.Println(pad(row.String()) + n.text)
		for _, d := range n.detail {
			fmt.Println(pad(gap.String()) + "  " + d)
		}
		for b, f := range forkAt {
			if f != i {
				continue
			}
			pc, bc := col[parent[b]], col[b]
			var link strings.Builder
			for c, ob := range order {
				switch {
				case c == pc:
					link.WriteString("├─")
				case c > pc && c < bc:
					link.WriteString("──")
				case c == bc:
					link.WriteString("╯ ")
				case below(ob, i):
					link.WriteString("│ ")
				default:
					link.WriteString("  ")
				}
			}
			fmt.Println(strings.TrimRight(link.String(), " "))
		}
	}
}

var logVerbose bool

var cmdLog = &cobra.Command{
	Use:   "log [-v]",
	Short: "Show the session's history as a tree: runs, checkpoints, branches",
	Long: `Newest first. @ is where you are, x a failed or interrupted run. Output and
hardware readings are left out; -v adds every result and the files each run changed.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		kvDir, err := session.Find()
		if err != nil {
			return err
		}
		sess, err := session.Load(kvDir)
		if err != nil {
			return err
		}
		if sess.Invocations == 0 {
			fmt.Println("Nothing recorded yet.")
			return nil
		}
		renderLog(sess, logNodes(sess, loadRuns(kvDir, sess), logVerbose))
		return nil
	},
}

// Files changed since the checkpoint the project is based on.
func workingState(kvDir string, sess *session.Session) (*session.Step, *provenance.Drift) {
	base := baseCheckpoint(sess)
	if base == nil {
		return nil, nil
	}
	m, err := provenance.LoadManifest(kvDir, base.ID)
	if err != nil {
		return base, nil
	}
	d := provenance.Compare(sess.ProjectDir, m)
	return base, &d
}

func printWorkingState(kvDir string, sess *session.Session) {
	if len(sess.Steps) == 0 {
		return
	}
	fmt.Printf("Branch:       %s\n", sess.CurrentBranch())
	base, d := workingState(kvDir, sess)
	if base == nil {
		return
	}
	fmt.Printf("Checkpoint:   %s\n", checkpointLabel(base))
	switch {
	case d == nil:
		fmt.Println("Files:        unknown (saved copy missing)")
	case d.Clean():
		fmt.Println("Files:        CLEAN, same as the checkpoint")
	default:
		fmt.Printf("Files:        CHANGED since the checkpoint\n")
		for _, f := range d.Modified {
			fmt.Printf("  modified  %s\n", f)
		}
		for _, f := range d.Added {
			fmt.Printf("  added     %s\n", f)
		}
		for _, f := range d.Deleted {
			fmt.Printf("  deleted   %s\n", f)
		}
	}
	if aside := sess.SetAside(); len(aside) > 0 {
		ids := make([]string, 0, len(aside))
		for id := range aside {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		fmt.Printf("Set aside:    %s\n", strings.Join(ids, ", "))
	}
}

func init() {
	cmdCheckpoint.Flags().StringVarP(&checkpointMsg, "message", "m", "", "what this point is, e.g. \"epoch 50 stable\"")
	cmdCheckpoint.Flags().StringSliceVar(&checkpointFiles, "files", nil, "extra files to save, such as a model checkpoint (comma separated)")
	cmdSetAside.Flags().StringVarP(&asideMsg, "message", "m", "", "why it is set aside")
	cmdSetAside.Flags().BoolVar(&asideUndo, "undo", false, "bring the run back into the main results")
	cmdLog.Flags().BoolVarP(&logVerbose, "verbose", "v", false, "show every result and changed file")
}

func historyCounts(steps []session.Step) string {
	n := map[string]int{}
	for _, st := range steps {
		n[st.Kind]++
	}
	var parts []string
	for _, k := range [][2]string{{"checkpoint", "checkpoints"}, {"restore", "restores"}, {"branch", "branches"},
		{"switch", "switches"}, {"set-aside", "set-asides"}, {"bring-back", "bring-backs"}} {
		switch c := n[k[0]]; c {
		case 0:
		case 1:
			parts = append(parts, "1 "+k[0])
		default:
			parts = append(parts, fmt.Sprintf("%d %s", c, k[1]))
		}
	}
	return strings.Join(parts, ", ")
}

func files(n int) string {
	if n == 1 {
		return "1 file"
	}
	return fmt.Sprintf("%d files", n)
}

func orDash(s string) string {
	if s == "" {
		return "no reason given"
	}
	return s
}
