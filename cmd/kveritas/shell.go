//go:build !windows

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/anchor"
	"github.com/Mamadou2727/kveritas-go/internal/client"
	"github.com/Mamadou2727/kveritas-go/internal/runner"
	"github.com/Mamadou2727/kveritas-go/internal/session"
	"github.com/creack/pty"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const markerPrefix = "\x1b]7701;"

var shellSkip = map[string]bool{
	"cd": true, "pushd": true, "popd": true, "dirs": true, "clear": true, "history": true,
	"exit": true, "logout": true, "kveritas": true, "kv": true, "export": true, "unset": true,
	"alias": true, "unalias": true, "source": true, ".": true, "jobs": true, "fg": true, "bg": true,
	"vi": true, "vim": true, "nvim": true, "nano": true, "emacs": true, "less": true, "more": true, "man": true,
}

var (
	ansiRe   = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\a\x1b]*(?:\a|\x1b\\)|\x1b[@-Z\\-_]`)
	assignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
)

var cmdShell = &cobra.Command{
	Use:   "shell",
	Short: "Open a recorded terminal: every command becomes a run",
	Long: `Opens your own shell (bash or zsh) with (kv) in the prompt. Every command you type
is a run, measured and anchored at the server when it ends, failed ones included.
Results are read from KV lines, or detected when autolog is on. On exit, kveritas
lists the latest results, lets you mark claims, and offers to seal.

With no session in the folder, it starts one and asks what the report shows
(redacted, names or open) and how to get results (declare, autolog or none).
Exit without sealing and the next kveritas shell continues the same session.

Not recorded: cd, export, source, clear, history, editors and pagers.
Linux and macOS, bash 4.4+ or zsh.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error { return runShell() },
}

type shellRec struct {
	kvDir    string
	sess     *session.Session
	c        *client.Client
	nonce    []byte
	fifo     string
	out      io.Writer
	shellPID int
	rec      *runner.Recorder
	inv      int
	line     []byte
	kept     []*session.RunRecord
	failed   int
	forged   bool
}

func runShell() error {
	if os.Getenv("KVERITAS_SHELL") != "" {
		return fmt.Errorf("already inside a kveritas shell")
	}
	if !interactive() || !term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("kveritas shell needs a terminal; in scripts use: kveritas run -- <command>")
	}
	kvDir, err := session.Find()
	if err != nil {
		if err := openOnThisMachine(initServer); err != nil {
			return err
		}
		initDisclosure = askDisclosure()
		if err := cmdInit.RunE(cmdInit, nil); err != nil {
			return err
		}
		if kvDir, err = session.Find(); err != nil {
			return err
		}
	}
	sess, err := session.Load(kvDir)
	if err != nil {
		return err
	}
	if sess.Sealed {
		return fmt.Errorf("session is already sealed; start a new one in another directory")
	}
	if sess.Type == "harness" {
		return fmt.Errorf("this is an agent session; the shell records experiment runs")
	}
	release, err := anchor.AcquireRun(kvDir)
	if err != nil {
		return err
	}
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	if err := recoverInterrupted(kvDir, sess); err != nil {
		return err
	}
	var c *client.Client
	if sess.ServerURL != "local" {
		c = client.New(sess.ServerURL)
		anchor.Flush(c, kvDir) //nolint:errcheck
		stop := anchor.Background(c, kvDir, 30*time.Second)
		defer stop()
	}
	if sess.Results == "" {
		askResults(kvDir, sess, "Every command in this shell is recorded as a run.")
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "kvshell-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	fifo := filepath.Join(dir, "ack")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		return err
	}
	sh, err := shellCommand(dir, hex.EncodeToString(nonce), fifo)
	if err != nil {
		return err
	}

	ptmx, err := pty.Start(sh)
	if err != nil {
		return err
	}
	defer ptmx.Close()
	_ = pty.InheritSize(os.Stdin, ptmx)
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	go func() {
		for range winch {
			_ = pty.InheritSize(os.Stdin, ptmx)
		}
	}()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP, syscall.SIGTERM)
	go func() {
		<-hup
		_ = sh.Process.Signal(syscall.SIGHUP)
	}()
	defer signal.Stop(winch)
	defer signal.Stop(hup)

	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "[kveritas] Recording. Each command is a run; type exit to finish.\r\n")
	done := make(chan struct{})
	go copyInput(ptmx, done)

	s := &shellRec{kvDir: kvDir, sess: sess, c: c, nonce: []byte(hex.EncodeToString(nonce)), fifo: fifo,
		out: os.Stdout, shellPID: sh.Process.Pid}
	s.pump(ptmx)
	_ = sh.Wait()
	close(done)
	s.end(-1)
	_ = term.Restore(int(os.Stdin.Fd()), state)

	names := s.summary()
	if len(s.sess.Runs) == 0 || !interactive() {
		return nil
	}
	if !confirm("Seal now? [Y/n] ") {
		fmt.Println("Seal later with: kveritas seal")
		return nil
	}
	release()
	released = true
	sealClaimNames = names
	return cmdSeal.RunE(cmdSeal, nil)
}

// The rc files delete themselves once read, so no command can learn the nonce and forge a boundary.
func shellCommand(dir, nonce, fifo string) (*exec.Cmd, error) {
	env := append(os.Environ(), "KVERITAS_SHELL="+strconv.Itoa(os.Getpid()))
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	if path := os.Getenv("SHELL"); filepath.Base(path) == "zsh" {
		zenv := filepath.Join(dir, ".zshenv")
		zrc := filepath.Join(dir, ".zshrc")
		orig := os.Getenv("ZDOTDIR")
		if orig == "" {
			orig = os.Getenv("HOME")
		}
		envScript := fmt.Sprintf(`__kv_zd=$ZDOTDIR
ZDOTDIR=%s
[ -f "$ZDOTDIR/.zshenv" ] && . "$ZDOTDIR/.zshenv"
ZDOTDIR=$__kv_zd
unset __kv_zd
`, q(orig))
		rcScript := fmt.Sprintf(`command rm -f -- %s %s
ZDOTDIR=%s
[ -f "$ZDOTDIR/.zshrc" ] && . "$ZDOTDIR/.zshrc"
typeset -g __kv_n=%s __kv_f=%s
__kv_pre() {
  printf '\033]7701;%%s;start;%%s\007' "$__kv_n" "$(printf %%s "${1:-$3}" | base64 | tr -d '\n')"
  read -r -t 30 __kv_a < "$__kv_f"
}
__kv_post() {
  local s=$?
  printf '\033]7701;%%s;end;%%s\007' "$__kv_n" "$s"
  read -r -t 600 __kv_a < "$__kv_f"
  return $s
}
preexec_functions+=(__kv_pre)
precmd_functions=(__kv_post $precmd_functions)
PROMPT="(kv) $PROMPT"
`, q(zenv), q(zrc), q(orig), q(nonce), q(fifo))
		if err := os.WriteFile(zenv, []byte(envScript), 0600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(zrc, []byte(rcScript), 0600); err != nil {
			return nil, err
		}
		cmd := exec.Command(path, "-i")
		cmd.Env = append(env, "ZDOTDIR="+dir)
		return cmd, nil
	}

	bash, err := exec.LookPath("bash")
	if err != nil {
		return nil, fmt.Errorf("kveritas shell needs bash or zsh")
	}
	out, _ := exec.Command(bash, "-c", `echo $((BASH_VERSINFO[0]*100+BASH_VERSINFO[1]))`).Output()
	if v, _ := strconv.Atoi(strings.TrimSpace(string(out))); v < 404 {
		return nil, fmt.Errorf("kveritas shell needs bash 4.4 or later, or zsh")
	}
	rc := filepath.Join(dir, "bashrc")
	script := fmt.Sprintf(`command rm -f -- %s
[ -f ~/.bashrc ] && . ~/.bashrc
__kv_n=%s
__kv_f=%s
export -n __kv_n __kv_f
HISTCONTROL=${HISTCONTROL//ignoreboth/ignoredups}
HISTCONTROL=${HISTCONTROL//ignorespace/}
HISTIGNORE=
__kv_pre() {
  local c
  c=$(HISTTIMEFORMAT= builtin history 1)
  [[ $c =~ ^[[:space:]]*[0-9]+\*?[[:space:]]+(.*)$ ]] && c=${BASH_REMATCH[1]}
  printf '\033]7701;%%s;start;%%s\007' "$__kv_n" "$(printf %%s "$c" | base64 | tr -d '\n')" >&2
  read -r -t 30 __kv_a < "$__kv_f"
}
__kv_post() {
  local s=$?
  printf '\033]7701;%%s;end;%%s\007' "$__kv_n" "$s"
  read -r -t 600 __kv_a < "$__kv_f"
  return $s
}
PS0='$(__kv_pre)'
if (( BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1] >= 501 )); then
  PROMPT_COMMAND=(__kv_post "${PROMPT_COMMAND[@]}")
else
  PROMPT_COMMAND="__kv_post${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
fi
PS1="(kv) $PS1"
`, q(rc), q(nonce), q(fifo))
	if err := os.WriteFile(rc, []byte(script), 0600); err != nil {
		return nil, err
	}
	cmd := exec.Command(bash, "--rcfile", rc, "-i")
	cmd.Env = env
	return cmd, nil
}

// Polls so the copier stops with the shell instead of eating the first key at the seal prompt.
func copyInput(dst io.Writer, done <-chan struct{}) {
	fd := int(os.Stdin.Fd())
	buf := make([]byte, 4096)
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		select {
		case <-done:
			return
		default:
		}
		n, err := unix.Poll(fds, 100)
		if err != nil && err != unix.EINTR {
			return
		}
		if n <= 0 {
			continue
		}
		m, err := unix.Read(fd, buf)
		if m > 0 {
			if _, werr := dst.Write(buf[:m]); werr != nil {
				return
			}
		}
		if m == 0 && err == nil {
			return
		}
		if err != nil && err != unix.EINTR && err != unix.EAGAIN {
			return
		}
	}
}

func (s *shellRec) pump(r io.Reader) {
	buf := make([]byte, 32*1024)
	var pend []byte
	for {
		n, err := r.Read(buf)
		if n > 0 {
			pend = s.scan(append(pend, buf[:n]...))
		}
		if err != nil {
			break
		}
	}
	s.emit(pend)
}

func (s *shellRec) scan(b []byte) []byte {
	for {
		i := bytes.Index(b, []byte(markerPrefix))
		if i < 0 {
			keep := partialPrefix(b, markerPrefix)
			s.emit(b[:len(b)-keep])
			return append([]byte(nil), b[len(b)-keep:]...)
		}
		s.emit(b[:i])
		rest := b[i+len(markerPrefix):]
		j := bytes.IndexByte(rest, '\a')
		if j < 0 {
			if len(rest) > 1<<16 {
				s.emit(b[i:])
				return nil
			}
			return append([]byte(nil), b[i:]...)
		}
		s.marker(string(rest[:j]))
		b = rest[j+1:]
	}
}

func partialPrefix(b []byte, prefix string) int {
	for k := min(len(prefix)-1, len(b)); k > 0; k-- {
		if bytes.HasSuffix(b, []byte(prefix[:k])) {
			return k
		}
	}
	return 0
}

func (s *shellRec) emit(b []byte) {
	if len(b) == 0 {
		return
	}
	s.out.Write(b) //nolint:errcheck
	if s.rec == nil {
		return
	}
	for _, c := range b {
		if c == '\n' {
			s.flushLine()
			continue
		}
		if len(s.line) < 1<<16 {
			s.line = append(s.line, c)
		}
	}
}

func (s *shellRec) flushLine() {
	if s.rec == nil || s.line == nil {
		return
	}
	l := ansiRe.ReplaceAllString(string(s.line), "")
	l = strings.TrimRight(l, "\r")
	if i := strings.LastIndexByte(l, '\r'); i >= 0 {
		l = l[i+1:]
	}
	s.line = nil
	s.rec.Line(l)
}

func (s *shellRec) say(format string, a ...any) {
	fmt.Fprintf(s.out, "[kveritas] "+format+"\r\n", a...)
}

func (s *shellRec) marker(body string) {
	parts := strings.SplitN(body, ";", 3)
	if len(parts) != 3 || subtle.ConstantTimeCompare([]byte(parts[0]), s.nonce) != 1 {
		if !s.forged {
			s.forged = true
			s.say("Warning: output contained a run marker without this shell's secret; ignored")
		}
		return
	}
	switch parts[1] {
	case "start":
		text, _ := base64.StdEncoding.DecodeString(parts[2])
		s.start(string(text))
	case "end":
		code, err := strconv.Atoi(parts[2])
		if err != nil {
			code = -1
		}
		s.end(code)
	default:
		return
	}
	s.ack()
}

func (s *shellRec) ack() {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		f, err := os.OpenFile(s.fifo, os.O_WRONLY|unix.O_NONBLOCK, 0)
		if err == nil {
			f.Write([]byte("ok\n")) //nolint:errcheck
			f.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func commandWords(text string) []string {
	words := strings.Fields(text)
	for len(words) > 0 && assignRe.MatchString(words[0]) {
		words = words[1:]
	}
	return words
}

// The child is not forked until the ack, so measuring starts before its first instruction.
func (s *shellRec) start(text string) {
	text = strings.TrimSpace(text)
	words := commandWords(text)
	if s.rec != nil || len(words) == 0 {
		return
	}
	if shellSkip[filepath.Base(words[0])] && !strings.ContainsAny(text, ";&|") {
		return
	}
	if fresh, err := session.Load(s.kvDir); err == nil {
		s.sess = fresh
	}
	var hints []string
	for _, w := range words {
		if isSourceFile(w) {
			hints = append(hints, w)
		}
	}
	inv := s.sess.Invocations
	if err := anchor.BeginRun(s.kvDir, anchor.Inflight{Invocation: inv, Index: len(s.sess.Runs), Command: words, StartedAt: time.Now().UTC()}); err != nil {
		s.say("Warning: run not recorded: %v", err)
		return
	}
	rec, err := runner.NewRecorder(s.sess, words, hints, runner.Options{Autolog: s.sess.Results == "autolog", Launch: "shell", Log: io.Discard})
	if err != nil {
		anchor.EndRun(s.kvDir)
		s.say("Warning: run not recorded: %v", err)
		return
	}
	rec.Attach(s.shellPID)
	s.rec, s.inv = rec, inv
}

func (s *shellRec) end(code int) {
	if s.rec == nil {
		return
	}
	if len(s.line) > 0 {
		s.flushLine()
	}
	res, err := s.rec.Finish(code)
	s.rec = nil
	if err != nil {
		anchor.EndRun(s.kvDir)
		s.say("Warning: run not recorded: %v", err)
		return
	}
	rec := res.Record
	if err := recordInvocation(s.kvDir, s.sess, rec, s.inv, nil); err != nil {
		s.say("Warning: run not recorded: %v", err)
		return
	}
	if s.c != nil {
		go anchor.Flush(s.c, s.kvDir) //nolint:errcheck
	}
	if code != 0 {
		s.failed++
		s.say("Run %d failed (exit %d): anchored, not kept in the report", s.inv+1, code)
		return
	}
	s.kept = append(s.kept, rec)
	results := 0
	for _, m := range rec.Metrics {
		if m.Source != "measured" {
			results++
		}
	}
	s.say("Run %d recorded: %d result(s), %s", s.inv+1, results, rec.DurationFmt)
}

func (s *shellRec) summary() []string {
	fmt.Printf("\n[kveritas] Shell closed: %d run(s) kept, %d failed\n", len(s.kept), s.failed)
	if len(s.kept) == 0 {
		return nil
	}
	latest := map[string]session.Metric{}
	runOf := map[string]int{}
	for _, r := range s.kept {
		for _, m := range r.Metrics {
			if m.Source != "measured" {
				latest[m.Name] = m
				runOf[m.Name] = r.Invocation + 1
			}
		}
	}
	if len(latest) == 0 {
		fmt.Println("[kveritas] No results declared; each run still has its measured time, memory and GPU use.")
		return nil
	}
	names := make([]string, 0, len(latest))
	for n := range latest {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Println("[kveritas] Latest results:")
	for _, n := range names {
		m := latest[n]
		fmt.Printf("  %-28s %-14.6g run %-4d %s\n", n, m.Value, runOf[n], m.Source)
	}
	if !interactive() {
		return nil
	}
	in := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Claims to mark (names separated by spaces, Enter for none): ")
		line, _ := in.ReadString('\n')
		picked := strings.Fields(strings.ReplaceAll(line, ",", " "))
		bad := ""
		for _, p := range picked {
			if _, ok := latest[p]; !ok {
				bad = p
				break
			}
		}
		if bad == "" {
			return picked
		}
		fmt.Printf("No result named %q\n", bad)
	}
}

func askDisclosure() string {
	fmt.Fprint(os.Stderr, `[kveritas] New session. What should the report show?
  1  Redacted: results only, no file names or code
  2  Names: file names, no code
  3  Open: your code too (needed to publish a record)
Choice [1]: `)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.TrimSpace(line) {
	case "2":
		return "names"
	case "3":
		return "open"
	}
	return "redacted"
}

func confirm(prompt string) bool {
	fmt.Print(prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "" || a == "y" || a == "yes"
}
