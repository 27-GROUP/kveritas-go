package main

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/anchor"
	"github.com/Mamadou2727/kveritas-go/internal/provenance"
	"github.com/Mamadou2727/kveritas-go/internal/session"
	"github.com/spf13/cobra"
)

//go:embed web
var webFiles embed.FS

var (
	webPort   int
	webNoOpen bool
)

var cmdWeb = &cobra.Command{
	Use:   "web [--port N] [--no-open]",
	Short: "Open the session's history in your browser",
	Long: `Serves the session's history on this machine only (127.0.0.1) and opens it in
your browser: the tree of runs, checkpoints and branches, the files changed since
your checkpoint, and buttons for checkpoint, restore, branch and set-aside. Every
action is the same as the command of that name and is anchored the same way.

The link carries a secret token, so other users of the machine cannot use it. On a
remote machine, forward the port and open the link on your computer:
  ssh -L 7701:127.0.0.1:7701 <host>`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error { return serveWeb() },
}

type webServer struct {
	kvDir string
	token string
	hosts map[string]bool
	cache *provenance.HashCache
	mu    sync.Mutex
}

func serveWeb() error {
	kvDir, err := session.Find()
	if err != nil {
		return fmt.Errorf("no session here; start one with kveritas run, shell or init")
	}
	if kvDir, err = filepath.Abs(kvDir); err != nil {
		return err
	}
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", webPort))
	if err != nil {
		return fmt.Errorf("port %d is busy; pick another with --port: %w", webPort, err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	s := &webServer{
		kvDir: kvDir,
		token: hex.EncodeToString(secret),
		hosts: map[string]bool{fmt.Sprintf("127.0.0.1:%d", port): true, fmt.Sprintf("localhost:%d", port): true},
		cache: provenance.NewHashCache(),
	}
	static, err := fs.Sub(webFiles, "web")
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServer(http.FS(static)))
	mux.HandleFunc("GET /api/state", s.api(s.state))
	mux.HandleFunc("POST /api/checkpoint", s.api(s.checkpoint))
	mux.HandleFunc("POST /api/restore", s.api(s.restore))
	mux.HandleFunc("POST /api/branch", s.api(s.branch))
	mux.HandleFunc("POST /api/set-aside", s.api(s.setAside))

	// The token rides in the fragment, which browsers never send to a server or put in a Referer.
	url := fmt.Sprintf("http://127.0.0.1:%d/#%s", port, s.token)
	fmt.Printf("K-Veritas history: %s\n", url)
	if webNoOpen || !openBrowser(url) {
		fmt.Printf("Open that link in a browser. On a remote machine: ssh -L %d:127.0.0.1:%d <host>, then open it on your computer.\n", port, port)
	}
	fmt.Println("Ctrl+C to stop.")

	srv := &http.Server{Handler: s.guard(mux), ReadHeaderTimeout: 10 * time.Second}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	go func() {
		<-stop
		_ = srv.Close()
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Refusing any other Host header stops a web page from reaching this server through
// DNS rebinding; the headers keep the page from being framed or leaking its URL.
func (s *webServer) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hosts[r.Host] {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *webServer) api(fn func(r *http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-KV-Token")), []byte(s.token)) != 1 {
			writeAPI(w, http.StatusUnauthorized, map[string]string{"error": "open the link printed in your terminal"})
			return
		}
		if r.Method == http.MethodPost && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeAPI(w, http.StatusUnsupportedMediaType, map[string]string{"error": "expected JSON"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		out, err := fn(r)
		if err != nil {
			writeAPI(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeAPI(w, http.StatusOK, out)
	}
}

func writeAPI(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decode(r *http.Request, v any) error {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

type webState struct {
	Gone       bool              `json:"gone,omitempty"`
	SessionID  string            `json:"session"`
	Disclosure string            `json:"disclosure"`
	Online     bool              `json:"online"`
	Branch     string            `json:"branch"`
	Branches   []string          `json:"branches"`
	Checkpoint *session.Step     `json:"checkpoint,omitempty"`
	Files      *provenance.Drift `json:"files,omitempty"`
	Clean      bool              `json:"clean"`
	Queued     int               `json:"queued"`
	Busy       string            `json:"busy,omitempty"`
	Columns    []string          `json:"columns"`
	Rows       []graphRow        `json:"rows"`
	Nodes      []logNode         `json:"nodes"`
}

func (s *webServer) state(r *http.Request) (any, error) {
	sess, err := session.Load(s.kvDir)
	if err != nil {
		if _, serr := os.Stat(s.kvDir); os.IsNotExist(serr) {
			return webState{Gone: true}, nil
		}
		return nil, err
	}
	runs := loadRuns(s.kvDir, sess)
	nodes := logNodes(sess, runs)
	cols, rows := graphLayout(sess, nodes)
	st := webState{
		SessionID: sess.ID, Disclosure: sess.Disclosure, Online: sess.ServerURL != "local",
		Branch: sess.CurrentBranch(), Branches: branches(sess, runs),
		Queued: len(anchor.Pending(s.kvDir)), Columns: cols, Rows: rows, Nodes: nodes,
	}
	if st.Disclosure == "" {
		st.Disclosure = "redacted"
	}
	if base := baseCheckpoint(sess); base != nil {
		st.Checkpoint = base
		if m, err := provenance.LoadManifest(s.kvDir, base.ID); err == nil {
			d := provenance.CompareCached(sess.ProjectDir, m, s.cache)
			st.Files, st.Clean = &d, d.Clean()
		}
	}
	if pid, held := anchor.RunLockHolder(s.kvDir); held && os.Getenv("KVERITAS_SHELL") != strconv.Itoa(pid) {
		st.Busy = "A run or a kveritas shell is using this session. Actions work once it finishes."
	} else if _, running := anchor.LoadInflight(s.kvDir); running {
		st.Busy = "A command is running. Actions work once it finishes."
	}
	return st, nil
}

// Every action goes through the same lock and the same code as its command.
func (s *webServer) act(fn func(sess *session.Session) ([]string, error)) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, sess, release, err := historySession(false)
	if err != nil {
		return nil, err
	}
	defer release()
	msgs, err := fn(sess)
	if err != nil {
		return nil, err
	}
	return map[string][]string{"messages": msgs}, nil
}

func (s *webServer) checkpoint(r *http.Request) (any, error) {
	var req struct {
		Message string   `json:"message"`
		Files   []string `json:"files"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	return s.act(func(sess *session.Session) ([]string, error) {
		st, err := saveCheckpoint(s.kvDir, sess, strings.TrimSpace(req.Message), req.Files)
		if err != nil {
			return nil, err
		}
		return []string{fmt.Sprintf("Checkpoint %s saved (%s)", checkpointLabel(st), files(st.Files))}, nil
	})
}

func (s *webServer) restore(r *http.Request) (any, error) {
	var req struct {
		ID string `json:"id"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	return s.act(func(sess *session.Session) ([]string, error) { return restoreTo(s.kvDir, sess, req.ID) })
}

func (s *webServer) branch(r *http.Request) (any, error) {
	var req struct {
		Name string `json:"name"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	return s.act(func(sess *session.Session) ([]string, error) {
		msg, err := switchBranch(s.kvDir, sess, strings.TrimSpace(req.Name))
		return []string{msg}, err
	})
}

func (s *webServer) setAside(r *http.Request) (any, error) {
	var req struct {
		Run    string `json:"run"`
		Reason string `json:"reason"`
		Undo   bool   `json:"undo"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	return s.act(func(sess *session.Session) ([]string, error) {
		msg, err := setAside(s.kvDir, sess, req.Run, strings.TrimSpace(req.Reason), req.Undo)
		return []string{msg}, err
	})
}

func openBrowser(url string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return false
		}
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start() == nil
}

func init() {
	cmdWeb.Flags().IntVar(&webPort, "port", 7701, "port on 127.0.0.1")
	cmdWeb.Flags().BoolVar(&webNoOpen, "no-open", false, "print the link without opening a browser")
}
