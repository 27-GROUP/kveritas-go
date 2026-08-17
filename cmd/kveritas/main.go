package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/bundle"
	"github.com/Mamadou2727/kveritas-go/internal/client"
	"github.com/Mamadou2727/kveritas-go/internal/compute"
	kvcrypto "github.com/Mamadou2727/kveritas-go/internal/crypto"
	"github.com/Mamadou2727/kveritas-go/internal/hardware"
	"github.com/Mamadou2727/kveritas-go/internal/harness"
	"github.com/Mamadou2727/kveritas-go/internal/hmca"
	"github.com/Mamadou2727/kveritas-go/internal/pdf"
	"github.com/Mamadou2727/kveritas-go/internal/provenance"
	"github.com/Mamadou2727/kveritas-go/internal/runner"
	"github.com/Mamadou2727/kveritas-go/internal/session"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

const defaultServer = "https://kveritas-api-production.up.railway.app"

var root = &cobra.Command{
	Use:   "kveritas",
	Short: "K-Veritas: tamper-evident experiment verification",
	Long: `K-Veritas cryptographically binds a published result to the exact
code, hardware, and time that produced it.

Workflow:
  kveritas init              Initialize a session in the current directory.
  kveritas run -- <cmd>      Run a monitored experiment.
  kveritas seal              Bundle and sign the session; produce a PDF report.
  kveritas verify <pdf>      Verify a signed report (no account required).
  kveritas check --claims c.json --report r.pdf
                             Check paper claims against signed results.
  kveritas generate-claims --report r.pdf
                             Generate a claims.json template from a report.
  kveritas status            Show current session state.
  kveritas update            Update to the latest version.

Protocol lines your script can emit:
  KVERITAS_METRIC   name=<id> value=<float> [step=<label>]
  KVERITAS_PHASE    name=<phase>
  KVERITAS_CLAIM    metric=<id> value=<float> [phase=<phase>]
  KVERITAS_INPUT    src=seed:<value>
  KVERITAS_MODEL    params=<int> arch=<name> precision=<fp16|bf16|fp32>
  KVERITAS_WORKLOAD dataset_size=<int> epochs=<float> batch_size=<int> [seq_len=<int>]`,
	SilenceUsage: true,
}

var cmdClean = &cobra.Command{
	Use:   "clean",
	Short: "Remove the .kveritas session directory",
	Long: `Removes the .kveritas directory and all session data.
Use this to abandon an in-progress session or clean up after a failed run.
This action is irreversible -- the session token is lost.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		kvDir, err := session.Find()
		if err != nil {
			return fmt.Errorf("no session found to clean")
		}
		if err := os.RemoveAll(kvDir); err != nil {
			return fmt.Errorf("removing session directory: %w", err)
		}
		fmt.Println("Session directory removed.")
		return nil
	},
}

func main() {
	root.AddCommand(cmdInit, cmdRun, cmdRecord, cmdSeal, cmdVerify, cmdCheck, cmdStatus, cmdGenerateClaims, cmdUpdate, cmdClean)
	root.AddCommand(cmdProve, cmdVerifyProof, cmdCheckout)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

var proveProject string
var proveOutput string

// cmdProve reveals one file against a signed snapshot without exposing the others.
// cmdProve reveals one or more files against a signed snapshot without exposing
// the others, as a single self-contained proof that embeds the report's seal.
var cmdProve = &cobra.Command{
	Use:   "prove <report.pdf> <file> [file...]",
	Short: "Prove one or more files were part of a signed snapshot, revealing nothing else",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		reportPath, files := args[0], args[1:]
		meta, err := pdf.ExtractMetadata(reportPath)
		if err != nil {
			return err
		}
		ks, err := provenance.LoadKeystore(provKeyPath(reportPath))
		if err != nil {
			return fmt.Errorf("reading proof keystore next to the report: %w", err)
		}
		project := proveProject
		if project == "" {
			project, _ = os.Getwd()
		}

		proof := &provenance.Proof{Kind: "kveritas-proof", Seal: meta.Seal}
		for _, rel := range files {
			pf, err := ks.BuildProofFile(project, rel)
			if err != nil {
				return err
			}
			proof.Files = append(proof.Files, *pf)
		}

		data, err := json.MarshalIndent(proof, "", "  ")
		if err != nil {
			return err
		}
		out := proveOutput
		if out == "" {
			out = "kveritas-proof.json"
		}
		if err := os.WriteFile(out, data, 0644); err != nil {
			return err
		}
		fmt.Printf("Proof written: %s (%d file(s))\n", out, len(proof.Files))
		for _, pf := range proof.Files {
			fmt.Printf("  %s  (run %d, %s)\n", pf.Path, pf.Run, pf.Event.Kind)
		}
		fmt.Println("Share this one file to prove those files; everything else stays hidden.")
		return nil
	},
}

// cmdVerifyProof checks a self-contained proof, or a proof against a report.
var cmdVerifyProof = &cobra.Command{
	Use:   "verify-proof <proof.json> | <report.pdf> <proof.json>",
	Short: "Check a selective-disclosure proof",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		proofPath := args[len(args)-1]
		data, err := os.ReadFile(proofPath)
		if err != nil {
			return err
		}
		var proof provenance.Proof
		if err := json.Unmarshal(data, &proof); err != nil {
			return err
		}

		seal := proof.Seal
		if len(args) == 2 {
			meta, err := pdf.ExtractMetadata(args[0])
			if err != nil {
				return err
			}
			seal = meta.Seal
		}
		if seal == nil {
			return fmt.Errorf("proof has no embedded seal; pass the report: verify-proof <report.pdf> <proof.json>")
		}
		if err := verifyReportSignature(seal); err != nil {
			return fmt.Errorf("report signature: %w", err)
		}

		roots := provenance.SignedRoots(seal.CanonicalJSON)
		ok := 0
		for _, pf := range proof.Files {
			if err := provenance.VerifyFile(&pf, roots); err != nil {
				fmt.Printf("REJECTED  %s  (%s)\n", pf.Path, err)
				continue
			}
			content, _ := base64.StdEncoding.DecodeString(pf.ContentB64)
			fmt.Printf("VERIFIED  %s  (run %d, %s, %d bytes)\n", pf.Path, pf.Run, pf.Event.Kind, len(content))
			ok++
		}
		fmt.Printf("%d of %d file(s) verified against the signed report.\n", ok, len(proof.Files))
		if ok != len(proof.Files) {
			return fmt.Errorf("some files did not verify")
		}
		return nil
	},
}

var checkoutReport string

// cmdCheckout materializes a snapshot's files from an open-disclosure bundle.
var cmdCheckout = &cobra.Command{
	Use:   "checkout <bundle.zip> <[run:]phase|index> <outdir>",
	Short: "Reconstruct the files of a snapshot from a checkout bundle",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		if checkoutReport != "" {
			if err := checkBundleBinding(checkoutReport, args[0]); err != nil {
				return err
			}
		} else {
			fmt.Fprintln(os.Stderr, "[kveritas] Note: pass --report <report.pdf> to verify the bundle against the signature.")
		}
		n, err := provenance.Checkout(args[0], args[1], args[2])
		if err != nil {
			return err
		}
		fmt.Printf("Checked out %d files from snapshot %q into %s\n", n, args[1], args[2])
		return nil
	},
}

func provKeyPath(reportPath string) string {
	return reportPath + ".provkey.json"
}

func provBundlePath(reportPath string) string {
	return reportPath + ".kvbundle.zip"
}

func verifyReportSignature(seal *session.SealRecord) error {
	if seal == nil || seal.CanonicalJSON == "" {
		return fmt.Errorf("report has no signed data")
	}
	if kvcrypto.HashBytes([]byte(seal.CanonicalJSON)) != seal.DataHash {
		return fmt.Errorf("data hash mismatch")
	}
	pub, err := kvcrypto.LoadPublicKey([]byte(seal.PublicKeyPEM))
	if err != nil {
		return err
	}
	payload := kvcrypto.Payload(seal.DataHash, seal.Nonce, seal.SignedAt)
	return kvcrypto.VerifyPSS(pub, payload, seal.Signature)
}

func checkBundleBinding(reportPath, bundlePath string) error {
	meta, err := pdf.ExtractMetadata(reportPath)
	if err != nil {
		return err
	}
	if err := verifyReportSignature(meta.Seal); err != nil {
		return fmt.Errorf("report signature: %w", err)
	}
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return err
	}
	if kvcrypto.HashBytes(data) == meta.Seal.CheckoutBundleHash {
		return nil
	}
	return fmt.Errorf("TAMPERED: bundle hash does not match the signed report")
}

var (
	initServer     string
	initLocal      bool
	initHarness    bool
	initDesignate  string
	initAgent      string
	initOperator   string
	initDisclosure string
	initShowNames  bool
)

const defaultDesignation = `{"designate":["tool_call","file_effect","model_turn","spawn","self_claim","approval"]}`

var cmdInit = &cobra.Command{
	Use:   "init",
	Short: "Initialize a K-Veritas session in the current directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		kvDir := filepath.Join(".", session.DirName)
		if _, err := os.Stat(kvDir); err == nil {
			return fmt.Errorf("session already exists in %s; use 'kveritas status' to inspect it", kvDir)
		}

		if err := os.MkdirAll(kvDir, 0700); err != nil {
			return err
		}

		wd, err := os.Getwd()
		if err != nil {
			return err
		}

		machineID := hardware.MachineID()
		sessionID := uuid.New().String()

		if initHarness {
			if err := harnessInit(kvDir, wd, machineID, sessionID); err != nil {
				_ = os.RemoveAll(kvDir)
				return err
			}
			return nil
		}

		var token string
		serverURL := initServer

		if !initLocal {
			c := client.New(serverURL)
			initResp, err := c.Init(sessionID, machineID, time.Now())
			if err != nil {
				_ = os.RemoveAll(kvDir)
				return fmt.Errorf("server registration failed: %w\n\nStart the server with: kveritas-server\nOr use --local for offline mode.", err)
			}
			token = initResp.Token
		} else {
			token = "local"
			serverURL = "local"
		}

		// --show-names keeps real file names in the report without bundling content.
		if initShowNames && initDisclosure == "redacted" {
			initDisclosure = "names"
		}

		salt, err := kvcrypto.RandomNonce()
		if err != nil {
			return err
		}

		sess := &session.Session{
			ID:         sessionID,
			InitAt:     time.Now().UTC(),
			ProjectDir: wd,
			MachineID:  machineID,
			Token:      token,
			ServerURL:  serverURL,
			Runs:       []string{},
			Disclosure: initDisclosure,
			ProvSalt:   salt,
		}

		if err := sess.Save(kvDir); err != nil {
			return err
		}

		fmt.Printf("Session initialized: %s\n", sessionID)
		fmt.Printf("Disclosure: %s\n", initDisclosure)
		return nil
	},
}

func init() {
	cmdInit.Flags().StringVar(&initServer, "server", defaultServer, "attestation server URL")
	cmdInit.Flags().BoolVar(&initLocal, "local", false, "local mode: sign with a local key, no server")
	cmdInit.Flags().BoolVar(&initHarness, "harness", false, "harness mode: record a hash-chained log of designated agent actions")
	cmdInit.Flags().StringVar(&initDesignate, "designate", "", "path to a designation policy file (default: all consequential actions)")
	cmdInit.Flags().StringVar(&initAgent, "agent", "unknown-agent", "agent identity (e.g. claude-code/<model>)")
	cmdInit.Flags().StringVar(&initOperator, "operator", "", "operator identity (default: current user)")
	cmdInit.Flags().StringVar(&initDisclosure, "disclosure", "redacted", "provenance disclosure: redacted (default), names, or open")
	cmdInit.Flags().BoolVar(&initShowNames, "show-names", false, "keep real file names in the report (no content bundled); same as --disclosure names")
	cmdProve.Flags().StringVar(&proveProject, "project", "", "project directory holding the files (default: current directory)")
	cmdProve.Flags().StringVarP(&proveOutput, "output", "o", "", "output proof path (default: kveritas-proof.json)")
	cmdCheckout.Flags().StringVar(&checkoutReport, "report", "", "report PDF to verify the bundle against before checkout")
}

// harnessInit registers a harness session and binds the designation D at genesis,
// signed by the attestation server so it cannot be altered after the session.
func harnessInit(kvDir, wd, machineID, sessionID string) error {
	designation := defaultDesignation
	if initDesignate != "" {
		data, err := os.ReadFile(initDesignate)
		if err != nil {
			return fmt.Errorf("reading designation policy: %w", err)
		}
		designation = string(data)
	}

	operator := initOperator
	if operator == "" {
		if u := os.Getenv("USER"); u != "" {
			operator = u
		} else {
			operator = "local"
		}
	}

	nonce, err := kvcrypto.RandomNonce()
	if err != nil {
		return err
	}

	g := &harness.Genesis{
		SessionID:       sessionID,
		MachineID:       machineID,
		AgentIdentity:   initAgent,
		OperatorID:      operator,
		Designation:     designation,
		DesignationHash: kvcrypto.HashBytes([]byte(designation)),
		StartAt:         time.Now().UTC().Format(time.RFC3339Nano),
		Nonce:           nonce,
	}
	gHash, err := g.CoreHash()
	if err != nil {
		return err
	}
	g.Hash = gHash

	serverURL := initServer
	token := "local"
	if initLocal {
		serverURL = "local"
		sig, err := localSignGenesis(gHash, sealKeyPath)
		if err != nil {
			return err
		}
		g.Server = *sig
	} else {
		c := client.New(serverURL)
		resp, err := c.HarnessInit(sessionID, machineID, time.Now(), gHash)
		if err != nil {
			return fmt.Errorf("server genesis registration failed: %w\n\nStart the server with: kveritas-server\nOr use --local for offline mode.", err)
		}
		token = resp.Token
		g.Server = harness.ServerSig{
			Signature:    resp.GenesisSignature,
			Nonce:        resp.GenesisNonce,
			SignedAt:     resp.GenesisSignedAt,
			PublicKeyPEM: resp.PublicKeyPEM,
		}
	}

	sess := &session.Session{
		ID:         sessionID,
		InitAt:     time.Now().UTC(),
		ProjectDir: wd,
		MachineID:  machineID,
		Token:      token,
		ServerURL:  serverURL,
		Type:       "harness",
		Runs:       []string{},
	}
	if err := sess.Save(kvDir); err != nil {
		return err
	}
	if err := harness.SaveGenesis(kvDir, g); err != nil {
		return err
	}

	hooksInstalled := true
	if err := installClaudeHooks(wd); err != nil {
		hooksInstalled = false
		fmt.Fprintf(os.Stderr, "[kveritas] Warning: could not install Claude Code hooks: %v\n", err)
	}

	fmt.Printf("Harness session initialized: %s\n", sessionID)
	fmt.Printf("Agent:       %s\n", g.AgentIdentity)
	fmt.Printf("Operator:    %s\n", g.OperatorID)
	fmt.Printf("Designation: %s (server-signed at genesis)\n", g.DesignationHash[:16])
	if hooksInstalled {
		fmt.Printf("Chokepoint:  Claude Code hooks installed in .claude/settings.json\n")
	}
	return nil
}

// installClaudeHooks registers the recording hooks in the project's Claude Code
// settings so every designated tool call and prompt is committed to the chain
// before it takes effect. Existing hooks are preserved.
func installClaudeHooks(projectDir string) error {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = "kveritas"
	}
	claudeDir := filepath.Join(projectDir, ".claude")
	if err := os.MkdirAll(claudeDir, 0755); err != nil {
		return err
	}
	settingsPath := filepath.Join(claudeDir, "settings.json")

	settings := map[string]interface{}{}
	if data, err := os.ReadFile(settingsPath); err == nil {
		_ = json.Unmarshal(data, &settings)
	}

	hooks, _ := settings["hooks"].(map[string]interface{})
	if hooks == nil {
		hooks = map[string]interface{}{}
	}
	entry := func(cmd string) interface{} {
		return map[string]interface{}{
			"matcher": "*",
			"hooks":   []interface{}{map[string]interface{}{"type": "command", "command": cmd}},
		}
	}
	ours := map[string]string{
		"PreToolUse":       exe + " record --hook pre",
		"PostToolUse":      exe + " record --hook post",
		"UserPromptSubmit": exe + " record --hook prompt",
	}
	for event, cmd := range ours {
		arr, _ := hooks[event].([]interface{})
		hooks[event] = append(arr, entry(cmd))
	}
	settings["hooks"] = hooks

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(settingsPath, data, 0644)
}

func localSignGenesis(gHash, keyPath string) (*harness.ServerSig, error) {
	if keyPath == "" {
		keyPath = "keys/private.pem"
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading private key %s: %w", keyPath, err)
	}
	privKey, err := kvcrypto.LoadPrivateKey(keyData)
	if err != nil {
		return nil, err
	}
	nonce, err := kvcrypto.RandomNonce()
	if err != nil {
		return nil, err
	}
	signedAt := time.Now().UTC().Format(time.RFC3339Nano)
	sig, err := kvcrypto.SignPSS(privKey, kvcrypto.Payload(gHash, nonce, signedAt))
	if err != nil {
		return nil, err
	}
	pubPEM, err := kvcrypto.MarshalPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return &harness.ServerSig{Signature: sig, Nonce: nonce, SignedAt: signedAt, PublicKeyPEM: string(pubPEM)}, nil
}

var (
	recordActor      string
	recordParent     string
	recordType       string
	recordInput      string
	recordInputFile  string
	recordOutput     string
	recordOutputFile string
	recordHook       string
)

var cmdRecord = &cobra.Command{
	Use:   "record",
	Short: "Append a designated agent action to the harness session chain",
	RunE: func(cmd *cobra.Command, args []string) error {
		if recordHook != "" {
			return runHookRecord(recordHook)
		}
		kvDir, err := session.Find()
		if err != nil {
			return err
		}
		sess, err := session.Load(kvDir)
		if err != nil {
			return err
		}
		if sess.Type != "harness" {
			return fmt.Errorf("record is only valid for harness sessions; use 'kveritas init --harness'")
		}
		if sess.Sealed {
			return fmt.Errorf("session is already sealed; cannot record more actions")
		}
		if recordType == "" {
			return fmt.Errorf("--type is required")
		}
		inHash, err := contentHash(recordInput, recordInputFile)
		if err != nil {
			return err
		}
		outHash, err := contentHash(recordOutput, recordOutputFile)
		if err != nil {
			return err
		}
		committed, err := harness.AppendEntry(kvDir, harness.Entry{
			Actor:       recordActor,
			ParentActor: recordParent,
			Type:        recordType,
			InputHash:   inHash,
			OutputHash:  outHash,
		})
		if err != nil {
			return err
		}
		fmt.Printf("Recorded entry %d: actor=%s type=%s\n", committed.Index, committed.Actor, committed.Type)
		return nil
	},
}

func contentHash(inline, file string) (string, error) {
	if file != "" {
		return kvcrypto.HashFile(file)
	}
	return kvcrypto.HashBytes([]byte(inline)), nil
}

func init() {
	cmdRecord.Flags().StringVar(&recordActor, "actor", "agent", "identity of the acting agent")
	cmdRecord.Flags().StringVar(&recordParent, "parent", "", "parent actor (for sub-agent actions)")
	cmdRecord.Flags().StringVar(&recordType, "type", "", "action type (tool_call, file_effect, model_turn, spawn, self_claim)")
	cmdRecord.Flags().StringVar(&recordInput, "input", "", "inline input content to hash")
	cmdRecord.Flags().StringVar(&recordInputFile, "input-file", "", "file whose content is the input")
	cmdRecord.Flags().StringVar(&recordOutput, "output", "", "inline output content to hash")
	cmdRecord.Flags().StringVar(&recordOutputFile, "output-file", "", "file whose content is the output")
	cmdRecord.Flags().StringVar(&recordHook, "hook", "", "Claude Code hook mode: pre, post, or prompt (reads the hook payload from stdin)")
}

type hookInput struct {
	SessionID     string          `json:"session_id"`
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	ToolResponse  json.RawMessage `json:"tool_response"`
	ToolUseID     string          `json:"tool_use_id"`
	AgentID       string          `json:"agent_id"`
	AgentType     string          `json:"agent_type"`
	Prompt        string          `json:"prompt"`
}

// topAgent names the independent top-level agent an action belongs to. Several
// agents can run under one chokepoint, so we take the name the launcher set in
// KVERITAS_AGENT_NAME, fall back to the harness session id (distinct per agent
// process), and finally to "main" for a lone agent.
func topAgent(h hookInput) string {
	if name := os.Getenv("KVERITAS_AGENT_NAME"); name != "" {
		return name
	}
	if h.SessionID != "" {
		return h.SessionID
	}
	return "main"
}

// hookActor names the agent that took an action, scoped under its top-level
// agent. Claude Code tags a sub-agent's tool calls with agent_type and agent_id;
// a top-level agent's own calls carry neither, so it is named by its top-level id.
func hookActor(h hookInput) string {
	top := topAgent(h)
	if h.AgentType != "" {
		id := h.AgentID
		if len(id) > 8 {
			id = id[:8]
		}
		return top + "/" + h.AgentType + "/" + id
	}
	return top
}

// spawnedAgentID pulls the child agent's id out of an Agent tool result, which
// is how a spawn is tied to the sub-agent it created.
func spawnedAgentID(resp json.RawMessage) string {
	var r struct {
		AgentID string `json:"agentId"`
	}
	_ = json.Unmarshal(resp, &r)
	return r.AgentID
}

// runHookRecord is invoked by a Claude Code hook. It reads the hook payload from
// stdin and commits a designated action to the chain before the tool is allowed
// to run. If a designated action cannot be recorded, the pre hook exits 2 to
// block the tool, so a designated effect cannot occur without its entry.
func runHookRecord(event string) error {
	data, _ := io.ReadAll(os.Stdin)
	var h hookInput
	_ = json.Unmarshal(data, &h)

	kvDir, err := session.Find()
	if err != nil {
		return nil
	}
	sess, err := session.Load(kvDir)
	if err != nil {
		// A session directory exists but cannot be read. Fail safe: block a pre
		// hook so a designated action cannot proceed while recording is disabled.
		if event == "pre" {
			fmt.Fprintf(os.Stderr, "kveritas: session unreadable; blocking tool to preserve the audit chain: %v\n", err)
			os.Exit(2)
		}
		return nil
	}
	if sess.Type != "harness" || sess.Sealed {
		return nil
	}

	actor := hookActor(h)
	top := topAgent(h)
	var e harness.Entry
	switch event {
	case "pre":
		if h.ToolName == "" {
			return nil
		}
		e = harness.Entry{Actor: actor, TopAgent: top, AgentID: h.AgentID, Type: mapToolType(h.ToolName), ToolUseID: h.ToolUseID, InputHash: kvcrypto.HashBytes(h.ToolInput)}
	case "post":
		if h.ToolName == "" {
			return nil
		}
		e = harness.Entry{Actor: actor, TopAgent: top, AgentID: h.AgentID, Type: mapToolType(h.ToolName) + ".result", ToolUseID: h.ToolUseID, OutputHash: kvcrypto.HashBytes(h.ToolResponse)}
		if h.ToolName == "Agent" || h.ToolName == "Task" {
			e.SpawnedID = spawnedAgentID(h.ToolResponse)
		}
	case "prompt":
		e = harness.Entry{Actor: "operator", TopAgent: top, Type: "prompt", InputHash: kvcrypto.HashBytes([]byte(h.Prompt))}
	default:
		return nil
	}

	if _, err := harness.AppendEntry(kvDir, e); err != nil {
		if event == "pre" {
			fmt.Fprintf(os.Stderr, "kveritas: could not record action; blocking tool to preserve the audit chain: %v\n", err)
			os.Exit(2)
		}
		return err
	}
	return nil
}

func mapToolType(tool string) string {
	switch tool {
	case "Agent", "Task":
		return "spawn"
	case "Write", "Edit", "MultiEdit", "NotebookEdit":
		return "file_effect"
	case "Bash":
		return "tool_call.exec"
	case "WebFetch", "WebSearch":
		return "tool_call.net"
	case "Read", "Glob", "Grep":
		return "tool_call.read"
	default:
		return "tool_call"
	}
}

// harnessSeal signs the final chain head and writes the verifiable session report.
func harnessSeal(kvDir string, sess *session.Session) error {
	g, err := harness.LoadGenesis(kvDir)
	if err != nil {
		return fmt.Errorf("loading genesis: %w", err)
	}
	entries, err := harness.LoadChain(kvDir)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("no actions recorded; use 'kveritas record' first")
	}
	chainHead := entries[len(entries)-1].Link

	var sealSig harness.ServerSig
	if sess.ServerURL == "local" || sealKeyPath != "" {
		s, err := localSignGenesis(chainHead, sealKeyPath)
		if err != nil {
			return err
		}
		sealSig = *s
	} else {
		c := client.New(sess.ServerURL)
		resp, err := c.Seal(sess, chainHead, len(entries))
		if err != nil {
			return fmt.Errorf("server seal failed: %w", err)
		}
		sealSig = harness.ServerSig{
			Signature:    resp.Signature,
			Nonce:        resp.Nonce,
			SignedAt:     resp.SignedAt,
			PublicKeyPEM: resp.PublicKeyPEM,
		}
	}

	report := harness.Report{
		Version: "1.0",
		Genesis: *g,
		Entries: entries,
		Seal: harness.Seal{
			ChainHead:  chainHead,
			EntryCount: len(entries),
			SealedAt:   time.Now().UTC().Format(time.RFC3339Nano),
			Server:     sealSig,
		},
	}

	outPath := sealOutput
	if outPath == "" {
		outPath = fmt.Sprintf("kveritas-session-%s.json", sess.ID[:8])
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		return err
	}

	sess.Sealed = true
	if err := sess.Save(kvDir); err != nil {
		return err
	}

	actors := map[string]int{}
	for _, e := range entries {
		actors[e.Actor]++
	}
	fmt.Printf("Session sealed: %s\n", outPath)
	fmt.Printf("Entries:     %d\n", len(entries))
	fmt.Printf("Chain head:  %s\n", chainHead)
	fmt.Printf("Attribution: %s\n", formatActorCounts(actors))
	return nil
}

func formatActorCounts(counts map[string]int) string {
	actors := make([]string, 0, len(counts))
	for a := range counts {
		actors = append(actors, a)
	}
	sort.Strings(actors)
	parts := make([]string, 0, len(actors))
	for _, a := range actors {
		parts = append(parts, fmt.Sprintf("%s=%d", a, counts[a]))
	}
	return strings.Join(parts, ", ")
}

func loadHarnessReport(path string) (*harness.Report, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var report harness.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, false
	}
	if report.Genesis.SessionID == "" || report.Seal.ChainHead == "" {
		return nil, false
	}
	return &report, true
}

func verifyHarnessReport(report *harness.Report) error {
	res := harness.Verify(report)
	g := report.Genesis

	fmt.Println(res.Verdict)
	if res.Verdict != "VERIFIED" {
		fmt.Printf("Reason: %s\n", res.Detail)
		if res.FailAtIndex > 0 {
			fmt.Printf("Localized: entry %d (actor %s)\n", res.FailAtIndex, res.FailAtActor)
		}
		return nil
	}

	fmt.Printf("Session:     %s\n", g.SessionID)
	fmt.Printf("Agent:       %s\n", g.AgentIdentity)
	fmt.Printf("Operator:    %s\n", g.OperatorID)
	fmt.Printf("Designation: %s (server-signed)\n", g.DesignationHash[:16])
	fmt.Printf("Started:     %s\n", g.StartAt)
	fmt.Printf("Sealed:      %s\n", report.Seal.SealedAt)
	fmt.Printf("Entries:     %d\n", res.EntryCount)
	fmt.Println("Actor tree:")
	renderActorTree(harness.ActorTree(report.Entries), 1)
	return nil
}

func renderActorTree(nodes []*harness.ActorNode, depth int) {
	for _, n := range nodes {
		fmt.Printf("%s%s (%d)\n", strings.Repeat("  ", depth), n.Name, n.Count)
		if len(n.Actions) > 0 {
			parts := make([]string, 0, len(n.Actions))
			for _, a := range n.Actions {
				parts = append(parts, fmt.Sprintf("%s:%d", a.Label, a.Count))
			}
			fmt.Printf("%s%s\n", strings.Repeat("  ", depth+1), strings.Join(parts, "  "))
		}
		renderActorTree(n.Children, depth+1)
	}
}

// sanitizeForReport returns a copy of the session safe to embed in the report.
// The provenance salt never leaves the machine, and the source file listing (real
// paths) is dropped unless the author disclosed names.
func sanitizeForReport(s *session.Session) *session.Session {
	clean := *s
	clean.ProvSalt = ""
	if provenance.ParseLevel(s.Disclosure) < provenance.Names {
		clean.SourceHashes = nil
	}
	return &clean
}

// renderProvenance prints the state timeline of a run: each snapshot, the event
// that produced it, and what changed since the previous one. At the redacted
// level file names are pseudonyms. Withheld files are listed so a reviewer sees
// what the author kept out of any bundle.
func renderProvenance(idx int, p *session.Provenance) {
	fmt.Printf("\nRun %d provenance (%s, %d files):\n", idx, p.Disclosure, p.FileCount)
	for _, c := range p.Commits {
		label := c.Event.Kind
		if c.Event.Name != "" {
			label += " " + c.Event.Name
		}
		root := c.Root
		if len(root) > 12 {
			root = root[:12]
		}
		fmt.Printf("  [%d] %-16s root %s", c.Index, label, root)
		if len(c.Changed) > 0 {
			fmt.Printf("  (%d changed)", len(c.Changed))
		}
		fmt.Println()
		for _, ch := range c.Changed {
			fmt.Printf("        %-6s %s\n", ch.Op, ch.Path)
		}
	}
	if len(p.Withheld) > 0 {
		fmt.Printf("  withheld by .kveritasignore (%d):\n", len(p.Withheld))
		for _, w := range p.Withheld {
			h := w.Hash
			if len(h) > 12 {
				h = h[:12]
			}
			fmt.Printf("        %s  %s  %s\n", w.Path, w.SizeBucket, h)
		}
	}
	if p.Truncated {
		fmt.Printf("  (provenance truncated at %d snapshots)\n", 512)
	}
}

// renderArtifacts prints the attested models and datasets. A public artifact
// shows its name and content hash (comparable to a published reference); a private
// one shows only a salted commitment.
func renderArtifacts(idx int, arts []session.Artifact) {
	fmt.Printf("\nRun %d attested artifacts:\n", idx)
	for _, a := range arts {
		name := a.Name
		if name == "" {
			name = "(private)"
		}
		h := a.Hash
		if len(h) > 16 {
			h = h[:16]
		}
		fmt.Printf("  %-8s %-18s %-8s %-6s %s\n", a.Role, name, a.Visibility, a.SizeBucket, h)
	}
}

// renderRunTrace prints the file and subprocess activity of a run as an event
// tree: what it read, what it produced, and what it spawned, in the order the
// events were observed.
func renderRunTrace(idx int, command []string, t *session.RunTrace) {
	var reads, writes []session.FileEvent
	for _, f := range t.Files {
		if f.Op == "write" {
			writes = append(writes, f)
		} else {
			reads = append(reads, f)
		}
	}

	fmt.Printf("\nRun %d activity: %s\n", idx, strings.Join(command, " "))
	if len(reads) > 0 {
		fmt.Printf("  read (%d):\n", len(reads))
		for _, f := range reads {
			fmt.Printf("    %s\n", f.Path)
		}
	}
	if len(writes) > 0 {
		fmt.Printf("  wrote (%d):\n", len(writes))
		for _, f := range writes {
			h := f.Hash
			if len(h) > 12 {
				h = h[:12]
			}
			fmt.Printf("    %s  %s\n", f.Path, h)
		}
	}
	if len(t.Procs) > 0 {
		fmt.Printf("  subprocesses (%d):\n", len(t.Procs))
		for _, p := range t.Procs {
			cmd := p.Command
			if cmd == "" {
				cmd = "(unknown)"
			}
			fmt.Printf("    [pid %d] %s\n", p.PID, cmd)
		}
	}
	if t.Truncated {
		fmt.Printf("  (trace truncated at %d files)\n", 10000)
	}
}

var runFiles []string

var cmdRun = &cobra.Command{
	Use:   "run [--files f1,f2] -- <command> [args...]",
	Short: "Run a monitored experiment",
	Long: `Executes <command> as a monitored subprocess.

The stdout stream is teed to your terminal and simultaneously hashed.
Metrics printed to stdout in the KVERITAS_METRIC format are captured:

  KVERITAS_METRIC name=val_accuracy value=0.9471 step=100

Phase boundaries trigger hardware snapshots:

  KVERITAS_PHASE name=eval

Inline claims are committed into the stdout hash:

  KVERITAS_CLAIM metric=accuracy value=0.9471 phase=eval

Seed commitments are recorded before computation:

  KVERITAS_INPUT src=seed:42

Files listed with --files are hashed before and after the run.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		kvDir, err := session.Find()
		if err != nil {
			return err
		}
		sess, err := session.Load(kvDir)
		if err != nil {
			return err
		}
		if sess.Sealed {
			return fmt.Errorf("session is already sealed; cannot add more runs")
		}

		// Heuristically detect the script file from the command if --files is empty.
		hints := runFiles
		if len(hints) == 0 {
			for _, arg := range args {
				if isSourceFile(arg) {
					hints = append(hints, arg)
				}
			}
		}

		rec, err := runner.Run(sess, args, hints)
		if err != nil {
			return err
		}

		// Record ALL runs to the server ledger (even failed ones) for the multi-run history.
		if sess.ServerURL != "local" {
			c := client.New(sess.ServerURL)
			if ledgerErr := c.RecordRun(sess, rec); ledgerErr != nil {
				fmt.Fprintf(os.Stderr, "[kveritas] Warning: could not record run in server ledger: %v\n", ledgerErr)
			}
		}

		if rec.ExitCode != 0 {
			fmt.Fprintf(os.Stderr, "[kveritas] Run failed with exit code %d -- discarding this run\n", rec.ExitCode)
			fmt.Fprintf(os.Stderr, "[kveritas] Fix the issue (dependencies, environment, etc.) and try again\n")
			return fmt.Errorf("command exited with code %d; only successful runs are recorded", rec.ExitCode)
		}

		if err := sess.SaveRun(kvDir, rec); err != nil {
			return err
		}

		sess.Runs = append(sess.Runs, rec.ID)
		if err := sess.Save(kvDir); err != nil {
			return err
		}

		fmt.Printf("Run %s recorded (%d metrics, %d claims, %d phases, %d seeds)\n",
			rec.ID, len(rec.Metrics), len(rec.Claims), len(rec.Phases), len(rec.Seeds))
		return nil
	},
}

func init() {
	cmdRun.Flags().StringSliceVar(&runFiles, "files", nil, "source files to hash (comma-separated)")
}

var (
	sealOutput  string
	sealKeyPath string
)

var cmdSeal = &cobra.Command{
	Use:   "seal",
	Short: "Bundle and cryptographically sign the session; produce a PDF report",
	RunE: func(cmd *cobra.Command, args []string) error {
		kvDir, err := session.Find()
		if err != nil {
			return err
		}
		sess, err := session.Load(kvDir)
		if err != nil {
			return err
		}
		if sess.Sealed {
			return fmt.Errorf("session is already sealed")
		}
		if sess.Type == "harness" {
			return harnessSeal(kvDir, sess)
		}
		if len(sess.Runs) == 0 {
			return fmt.Errorf("no runs recorded; use 'kveritas run' first")
		}

		runs := make([]*session.RunRecord, 0, len(sess.Runs))
		for _, id := range sess.Runs {
			r, err := session.LoadRun(kvDir, id)
			if err != nil {
				return fmt.Errorf("loading run %s: %w", id, err)
			}
			runs = append(runs, r)
		}

		if len(sess.SourceHashes) > 0 {
			modified, missing, err := bundle.VerifySourceIntegrity(sess.ProjectDir, sess.SourceHashes)
			if err != nil {
				return fmt.Errorf("source integrity check failed: %w", err)
			}
			if len(modified) > 0 {
				fmt.Fprintf(os.Stderr, "[kveritas] SEAL REFUSED: source files modified after experiment runs:\n")
				for _, f := range modified {
					fmt.Fprintf(os.Stderr, "  MODIFIED: %s\n", f)
				}
				return fmt.Errorf("source code was modified after experiments were run; results cannot be trusted")
			}
			if len(missing) > 0 {
				fmt.Fprintf(os.Stderr, "[kveritas] Warning: %d source files removed since runs\n", len(missing))
			}
		}

		var allSamples []session.HardwareSample
		for _, r := range runs {
			allSamples = append(allSamples, r.HardwareSamples...)
		}
		hmcaResult := hmca.Analyze(runs, allSamples)
		fmt.Fprintf(os.Stderr, "[kveritas] HMCA score: %.2f  verdict: %s\n", hmcaResult.Score, hmcaResult.Verdict)
		for _, f := range hmcaResult.Flags {
			fmt.Fprintf(os.Stderr, "[kveritas] HMCA flag: %s\n", f)
		}

		// The source bundle ships file contents, so it is only built when the author
		// The checkout bundle (open disclosure only) is the single bundle now; the
		// older flat source bundle is gone. Every run's store is merged into one zip
		// and its hash is bound into the signature below.
		var bundleHash string
		var combinedBundle []byte
		var checkoutBundleHash string
		var bundleInputs []provenance.BundleInput
		for _, r := range runs {
			if r.ProvBundleHash != "" {
				bundleInputs = append(bundleInputs, provenance.BundleInput{
					Run:  r.Index + 1,
					Path: filepath.Join(kvDir, "bundle-"+r.ID+".zip"),
				})
			}
		}
		if len(bundleInputs) > 0 {
			b, h, err := provenance.MergeBundles(bundleInputs)
			if err != nil {
				return fmt.Errorf("merging checkout bundles: %w", err)
			}
			combinedBundle = b
			checkoutBundleHash = h
		}

		dataHash, canonicalBytes, err := canonicalSessionHash(sess, runs, bundleHash, checkoutBundleHash, &hmcaResult)
		if err != nil {
			return fmt.Errorf("hashing session data: %w", err)
		}

		var seal *session.SealRecord

		if sess.ServerURL == "local" || sealKeyPath != "" {
			seal, err = localSeal(sess, runs, dataHash, sealKeyPath)
		} else {
			seal, err = serverSeal(sess, runs, dataHash)
		}
		if err != nil {
			return err
		}
		seal.SourceBundleHash = bundleHash
		seal.CheckoutBundleHash = checkoutBundleHash
		seal.CanonicalJSON = string(canonicalBytes)

		if sess.ServerURL != "local" {
			c := client.New(sess.ServerURL)
			history, err := c.RunHistory(sess)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[kveritas] Warning: could not retrieve run history: %v\n", err)
			} else {
				seal.RunHistory = history.Runs
				seal.TotalRunCount = history.TotalRuns
				fmt.Fprintf(os.Stderr, "[kveritas] Run history: %d total invocations for this session\n", history.TotalRuns)
			}
		}

		outPath := sealOutput
		if outPath == "" {
			outPath = fmt.Sprintf("kveritas-report-%s.pdf", sess.ID[:8])
		}

		if err := pdf.Generate(sanitizeForReport(sess), runs, seal, &hmcaResult, outPath); err != nil {
			return fmt.Errorf("PDF generation: %w", err)
		}

		// Merge every run's proof keystore into one sidecar so a proof can reveal a
		// file from any run, and write the single combined checkout bundle. Both are
		// kept next to the report before the session directory is cleaned up.
		merged := &provenance.Keystore{SessionID: sess.ID}
		for _, r := range runs {
			if k, err := provenance.LoadKeystore(filepath.Join(kvDir, "keystore-"+r.ID+".json")); err == nil {
				for i := range k.Commits {
					k.Commits[i].Run = r.Index + 1
				}
				merged.Commits = append(merged.Commits, k.Commits...)
			}
		}
		if len(combinedBundle) > 0 {
			if err := os.WriteFile(provBundlePath(outPath), combinedBundle, 0644); err == nil {
				fmt.Fprintf(os.Stderr, "[kveritas] Checkout bundle: %s (%d runs)\n", provBundlePath(outPath), len(bundleInputs))
			}
		}
		if len(merged.Commits) > 0 {
			if err := merged.Save(provKeyPath(outPath)); err == nil {
				fmt.Fprintf(os.Stderr, "[kveritas] Proof keystore: %s (keep local)\n", provKeyPath(outPath))
			}
		}

		if removeErr := os.RemoveAll(kvDir); removeErr != nil {
			fmt.Fprintf(os.Stderr, "[kveritas] Warning: could not remove session directory: %v\n", removeErr)
		} else {
			fmt.Fprintf(os.Stderr, "[kveritas] Session directory cleaned up\n")
		}

		fmt.Printf("Report sealed: %s\n", outPath)
		fmt.Printf("Data hash:     %s\n", seal.DataHash)
		fmt.Printf("Runs:          %d\n", len(runs))
		fmt.Printf("HMCA score:    %.2f (%s)\n", hmcaResult.Score, hmcaResult.Verdict)
		if seal.TotalRunCount > 0 {
			fmt.Printf("Total runs:    %d (including failed/discarded)\n", seal.TotalRunCount)
		}
		fmt.Println()

		for i, r := range runs {
			cmd := strings.Join(r.Command, " ")
			fmt.Printf("--- Run %d: %s (%s) ---\n", i+1, cmd, r.DurationFmt)
			if len(r.Metrics) == 0 {
				fmt.Printf("  (no metrics captured)\n")
			} else {
				for _, m := range r.Metrics {
					src := m.Source
					step := ""
					if m.Step != "" {
						step = fmt.Sprintf(" [step=%s]", m.Step)
					}
					fmt.Printf("  %-30s  %.6g  (%s)%s\n", m.Name, m.Value, src, step)
				}
			}
			if len(r.Claims) > 0 {
				fmt.Printf("  Claims:\n")
				for _, c := range r.Claims {
					phase := ""
					if c.Phase != "" {
						phase = fmt.Sprintf(" phase=%s", c.Phase)
					}
					fmt.Printf("    %-30s  %.6g  (line %d%s)\n", c.Metric, c.Value, c.Line, phase)
				}
			}
			if len(r.Seeds) > 0 {
				fmt.Printf("  Seed commitments:\n")
				for _, s := range r.Seeds {
					fmt.Printf("    %s (line %d)\n", s.Source, s.Line)
				}
			}
			reportComputeCert(compute.Analyze(r))
		}
		return nil
	},
}

// reportComputeCert prints a run's compute-cost certificate to stdout.
func reportComputeCert(c session.ComputeCert) {
	if c.Verdict == "" || c.Verdict == "N/A" {
		return
	}
	fmt.Printf("  Compute [%s]", c.Verdict)
	if c.FDeclaredFLOPs > 0 {
		fmt.Printf(" declared=%.2e FLOPs  active=%.0fs  energy=%.0fJ  peakmem=%.0fMB",
			c.FDeclaredFLOPs, c.GPUActiveSec, c.EnergyJoules, c.PeakGPUMemMB)
		if c.ImpliedMFU > 0 {
			fmt.Printf("  MFU=%.3f", c.ImpliedMFU)
		}
	}
	fmt.Println()
	for _, n := range c.Notes {
		fmt.Printf("    ! %s\n", n)
	}
}

func init() {
	cmdSeal.Flags().StringVarP(&sealOutput, "output", "o", "", "output PDF path (default: kveritas-report-<id>.pdf)")
	cmdSeal.Flags().StringVar(&sealKeyPath, "local-key", "", "path to local RSA private key PEM (for offline signing)")
}

func canonicalSessionHash(sess *session.Session, runs []*session.RunRecord, bundleHash, checkoutBundleHash string, hmcaResult *session.HMCAResult) (string, []byte, error) {
	type runPayload struct {
		ID          string               `json:"id"`
		Index       int                  `json:"index"`
		Command     []string             `json:"command"`
		StartAt     string               `json:"start_at"`
		EndAt       string               `json:"end_at"`
		DurationSec float64              `json:"duration_sec"`
		ExitCode    int                  `json:"exit_code"`
		PreHashes   map[string]string    `json:"pre_hashes"`
		PostHashes  map[string]string    `json:"post_hashes"`
		Modified    []string             `json:"modified_files"`
		StdoutHash  string               `json:"stdout_hash"`
		StderrHash  string               `json:"stderr_hash"`
		StdoutLines int                  `json:"stdout_lines"`
		Metrics     []session.Metric     `json:"metrics"`
		Hardware    session.HardwareInfo `json:"hardware"`
		EnvDigest   string               `json:"env_digest"`
		// New fields (omitted when empty for backward compat with old verifier)
		Phases         []session.PhaseEvent     `json:"phases,omitempty"`
		Claims         []session.InlineClaim    `json:"claims,omitempty"`
		Seeds          []session.SeedCommitment `json:"seeds,omitempty"`
		MetricHash     string                   `json:"metric_hash,omitempty"`
		DurationFmt    string                   `json:"duration_fmt,omitempty"`
		SourceCodeHash string                   `json:"source_code_hash,omitempty"`
		Declared       *session.DeclaredModel   `json:"declared,omitempty"`
		Trace          *session.RunTrace        `json:"trace,omitempty"`
		Provenance     *session.Provenance      `json:"provenance,omitempty"`
		ProvBundleHash string                   `json:"prov_bundle_hash,omitempty"`
		Artifacts      []session.Artifact       `json:"artifacts,omitempty"`
	}

	runPayloads := make([]runPayload, 0, len(runs))
	for _, r := range runs {
		rp := runPayload{
			ID:             r.ID,
			Index:          r.Index,
			Command:        r.Command,
			StartAt:        r.StartAt.UTC().Format(time.RFC3339Nano),
			EndAt:          r.EndAt.UTC().Format(time.RFC3339Nano),
			DurationSec:    r.DurationSec,
			ExitCode:       r.ExitCode,
			PreHashes:      r.PreHashes,
			PostHashes:     r.PostHashes,
			Modified:       r.Modified,
			StdoutHash:     r.StdoutHash,
			StderrHash:     r.StderrHash,
			StdoutLines:    r.StdoutLines,
			Metrics:        r.Metrics,
			Hardware:       r.Hardware,
			EnvDigest:      r.EnvDigest,
			Phases:         r.Phases,
			Claims:         r.Claims,
			Seeds:          r.Seeds,
			MetricHash:     r.MetricHash,
			DurationFmt:    r.DurationFmt,
			SourceCodeHash: r.SourceCodeHash,
			Declared:       r.Declared,
			Trace:          r.Trace,
			Provenance:     r.Provenance,
			ProvBundleHash: r.ProvBundleHash,
			Artifacts:      r.Artifacts,
		}
		runPayloads = append(runPayloads, rp)
	}

	// Compute-cost certificates are derived deterministically per run, so they are
	// recomputed identically at seal and verify; binding them into the signed data
	// makes any declared-card or sample tampering break the signature. They are
	// bound only when at least one run declares a model card, so reports without one
	// (including those from older versions) hash exactly as before.
	certs := make([]session.ComputeCert, 0, len(runs))
	anyDeclared := false
	for _, r := range runs {
		certs = append(certs, compute.Analyze(r))
		if r.Declared != nil {
			anyDeclared = true
		}
	}

	signingData := map[string]interface{}{
		"session_id": sess.ID,
		"init_at":    sess.InitAt.UTC().Format(time.RFC3339Nano),
		"machine_id": sess.MachineID,
		"server_url": sess.ServerURL,
		"runs":       runPayloads,
	}
	if bundleHash != "" {
		signingData["source_bundle_hash"] = bundleHash
	}
	if checkoutBundleHash != "" {
		signingData["checkout_bundle_hash"] = checkoutBundleHash
	}
	if hmcaResult != nil {
		signingData["hmca"] = hmcaResult
	}
	if anyDeclared {
		signingData["compute"] = certs
	}

	return kvcrypto.CanonicalHashWithBytes(signingData)
}

func serverSeal(sess *session.Session, runs []*session.RunRecord, dataHash string) (*session.SealRecord, error) {
	c := client.New(sess.ServerURL)
	resp, err := c.Seal(sess, dataHash, len(runs))
	if err != nil {
		return nil, fmt.Errorf("server attestation failed: %w\n\nEnsure the server is running: kveritas-server", err)
	}

	return &session.SealRecord{
		SessionID:         sess.ID,
		SealedAt:          time.Now().UTC(),
		DataHash:          dataHash,
		Nonce:             resp.Nonce,
		SignedAt:          resp.SignedAt,
		Signature:         resp.Signature,
		SignedMessageHash: resp.SignedMessageHash,
		PublicKeyPEM:      resp.PublicKeyPEM,
		ServerURL:         sess.ServerURL,
	}, nil
}

func localSeal(sess *session.Session, _ []*session.RunRecord, dataHash, keyPath string) (*session.SealRecord, error) {
	if keyPath == "" {
		keyPath = "keys/private.pem"
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading private key %s: %w\n\nGenerate a key with: kveritas-server --keys keys", keyPath, err)
	}
	privKey, err := kvcrypto.LoadPrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	nonce, err := kvcrypto.RandomNonce()
	if err != nil {
		return nil, err
	}
	signedAt := time.Now().UTC().Format(time.RFC3339Nano)
	payload := kvcrypto.Payload(dataHash, nonce, signedAt)

	sig, err := kvcrypto.SignPSS(privKey, payload)
	if err != nil {
		return nil, err
	}

	pubPEM, err := kvcrypto.MarshalPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &session.SealRecord{
		SessionID:         sess.ID,
		SealedAt:          time.Now().UTC(),
		DataHash:          dataHash,
		Nonce:             nonce,
		SignedAt:          signedAt,
		Signature:         sig,
		SignedMessageHash: kvcrypto.HashBytes([]byte(payload)),
		PublicKeyPEM:      string(pubPEM),
		ServerURL:         "local",
	}, nil
}

var verifyKeyPath string

var cmdVerify = &cobra.Command{
	Use:   "verify <report.pdf>",
	Short: "Verify a signed K-Veritas report (no account required)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		reportPath := args[0]

		if report, ok := loadHarnessReport(reportPath); ok {
			return verifyHarnessReport(report)
		}

		meta, err := pdf.ExtractMetadata(reportPath)
		if err != nil {
			return err
		}

		seal := meta.Seal
		sess := meta.Session
		runs := meta.Runs

		var verifySamples []session.HardwareSample
		for _, r := range runs {
			verifySamples = append(verifySamples, r.HardwareSamples...)
		}
		verifyHMCA := hmca.Analyze(runs, verifySamples)

		// Step 1: recompute and verify the data hash.
		computedHash, _, err := canonicalSessionHash(sess, runs, seal.SourceBundleHash, seal.CheckoutBundleHash, &verifyHMCA)
		if err != nil {
			return fmt.Errorf("hashing session data: %w", err)
		}
		if computedHash != seal.DataHash {
			fmt.Printf("TAMPERED\nData hash mismatch.\n  Stored:   %s\n  Computed: %s\n",
				seal.DataHash, computedHash)
			return nil
		}

		// Step 2: verify the signed message hash.
		payload := kvcrypto.Payload(seal.DataHash, seal.Nonce, seal.SignedAt)
		expectedMsgHash := kvcrypto.HashBytes([]byte(payload))
		if expectedMsgHash != seal.SignedMessageHash {
			fmt.Printf("TAMPERED\nSigned message hash mismatch.\n  Stored:   %s\n  Expected: %s\n",
				seal.SignedMessageHash, expectedMsgHash)
			return nil
		}

		// Step 3: verify RSA-PSS signature.
		pubKeyPEM := []byte(seal.PublicKeyPEM)
		if verifyKeyPath != "" {
			pubKeyPEM, err = os.ReadFile(verifyKeyPath)
			if err != nil {
				return fmt.Errorf("reading public key: %w", err)
			}
		}
		pubKey, err := kvcrypto.LoadPublicKey(pubKeyPEM)
		if err != nil {
			return fmt.Errorf("parsing public key: %w", err)
		}
		if err := kvcrypto.VerifyPSS(pubKey, payload, seal.Signature); err != nil {
			fmt.Printf("INVALID\nSignature verification failed: %v\n", err)
			return nil
		}

		fmt.Printf("VERIFIED\n")
		fmt.Printf("Session:    %s\n", sess.ID)
		fmt.Printf("Sealed at:  %s\n", seal.SealedAt.UTC().Format(time.RFC3339))
		fmt.Printf("Signed at:  %s\n", seal.SignedAt)
		fmt.Printf("Machine:    %s\n", sess.MachineID)
		fmt.Printf("Runs:       %d\n", len(runs))
		fmt.Printf("Data hash:  %s\n", seal.DataHash)

		if seal.TotalRunCount > 0 {
			fmt.Printf("Total invocations: %d (including failed/discarded)\n", seal.TotalRunCount)
		}

		explicitCount := 0
		claimCount := 0
		phaseCount := 0
		seedCount := 0
		for _, r := range runs {
			for _, m := range r.Metrics {
				if m.Source == "explicit" {
					explicitCount++
				}
			}
			claimCount += len(r.Claims)
			phaseCount += len(r.Phases)
			seedCount += len(r.Seeds)
		}
		fmt.Printf("Metrics:    %d explicit\n", explicitCount)
		if claimCount > 0 {
			fmt.Printf("Claims:     %d inline\n", claimCount)
		}
		if phaseCount > 0 {
			fmt.Printf("Phases:     %d boundaries\n", phaseCount)
		}
		if seedCount > 0 {
			fmt.Printf("Seeds:      %d commitments\n", seedCount)
		}

		for i, r := range runs {
			if r.Provenance != nil {
				renderProvenance(i+1, r.Provenance)
			}
			if len(r.Artifacts) > 0 {
				renderArtifacts(i+1, r.Artifacts)
			}
			if r.Trace != nil {
				renderRunTrace(i+1, r.Command, r.Trace)
			}
		}

		for i, r := range runs {
			if r.Declared == nil {
				continue
			}
			cert := compute.Analyze(r)
			fmt.Printf("Run %d compute:\n", i+1)
			reportComputeCert(cert)
		}
		return nil
	},
}

func init() {
	cmdVerify.Flags().StringVar(&verifyKeyPath, "public-key", "", "path to public key PEM (default: use key embedded in report)")
}

type claimsFile struct {
	Claims []claim `json:"claims"`
}

type claim struct {
	Metric    string  `json:"metric"`
	Value     float64 `json:"value"`
	Tolerance float64 `json:"tolerance"`
	Run       int     `json:"run,omitempty"` // 1-indexed; 0 means any run
}

var (
	checkClaimsPath string
	checkReportPath string
)

var cmdCheck = &cobra.Command{
	Use:   "check --claims <claims.json> --report <report.pdf>",
	Short: "Check paper claims against a signed report",
	RunE: func(cmd *cobra.Command, args []string) error {
		if checkClaimsPath == "" || checkReportPath == "" {
			return fmt.Errorf("--claims and --report are both required")
		}

		meta, err := pdf.ExtractMetadata(checkReportPath)
		if err != nil {
			return err
		}

		// Verify integrity first.
		seal := meta.Seal
		sess := meta.Session
		runs := meta.Runs

		var checkSamples []session.HardwareSample
		for _, r := range runs {
			checkSamples = append(checkSamples, r.HardwareSamples...)
		}
		checkHMCA := hmca.Analyze(runs, checkSamples)
		computedHash, _, err := canonicalSessionHash(sess, runs, seal.SourceBundleHash, seal.CheckoutBundleHash, &checkHMCA)
		if err != nil {
			return err
		}
		if computedHash != seal.DataHash {
			fmt.Println("TAMPERED: report data has been modified; claims check aborted")
			return nil
		}
		payload := kvcrypto.Payload(seal.DataHash, seal.Nonce, seal.SignedAt)
		if kvcrypto.HashBytes([]byte(payload)) != seal.SignedMessageHash {
			fmt.Println("TAMPERED: signature metadata has been modified; claims check aborted")
			return nil
		}
		pubKey, err := kvcrypto.LoadPublicKey([]byte(seal.PublicKeyPEM))
		if err != nil {
			return err
		}
		if err := kvcrypto.VerifyPSS(pubKey, payload, seal.Signature); err != nil {
			fmt.Printf("INVALID: signature verification failed: %v\n", err)
			return nil
		}

		claimsData, err := os.ReadFile(checkClaimsPath)
		if err != nil {
			return fmt.Errorf("reading claims file: %w", err)
		}
		var cf claimsFile
		if err := json.Unmarshal(claimsData, &cf); err != nil {
			return fmt.Errorf("parsing claims file: %w", err)
		}

		allOK := true
		for _, c := range cf.Claims {
			found, actual, ok := findMetric(runs, c.Metric, c.Run)
			if !found {
				fmt.Printf("MISSING   %s (not found in signed report)\n", c.Metric)
				allOK = false
				continue
			}
			diff := math.Abs(actual - c.Value)
			tol := c.Tolerance
			if tol == 0 {
				tol = 1e-4
			}
			if diff <= tol {
				fmt.Printf("CONSISTENT  %-30s  claimed=%.6g  signed=%.6g  diff=%.2e\n",
					c.Metric, c.Value, actual, diff)
			} else {
				fmt.Printf("INCONSISTENT %-30s  claimed=%.6g  signed=%.6g  diff=%.2e  tolerance=%.2e\n",
					c.Metric, c.Value, actual, diff, tol)
				allOK = false
				_ = ok
			}
		}

		if allOK {
			fmt.Println("\nResult: CONSISTENT")
		} else {
			fmt.Println("\nResult: INCONSISTENT")
		}
		return nil
	},
}

func init() {
	cmdCheck.Flags().StringVar(&checkClaimsPath, "claims", "", "path to claims JSON file")
	cmdCheck.Flags().StringVar(&checkReportPath, "report", "", "path to K-Veritas PDF report")
}

// findMetric searches runs for a metric by name.
// runFilter is 1-indexed; 0 means search all runs.
func findMetric(runs []*session.RunRecord, name string, runFilter int) (found bool, value float64, explicit bool) {
	for i, r := range runs {
		if runFilter > 0 && i+1 != runFilter {
			continue
		}
		for _, m := range r.Metrics {
			if strings.EqualFold(m.Name, name) {
				return true, m.Value, m.Source == "explicit"
			}
		}
	}
	return false, 0, false
}

var cmdStatus = &cobra.Command{
	Use:   "status",
	Short: "Show current session state",
	RunE: func(cmd *cobra.Command, args []string) error {
		kvDir, err := session.Find()
		if err != nil {
			return err
		}
		sess, err := session.Load(kvDir)
		if err != nil {
			return err
		}

		fmt.Printf("Session ID:   %s\n", sess.ID)
		fmt.Printf("Initialized:  %s\n", sess.InitAt.UTC().Format(time.RFC3339))
		fmt.Printf("Machine ID:   %s\n", sess.MachineID)
		fmt.Printf("Server:       %s\n", sess.ServerURL)
		fmt.Printf("Sealed:       %v\n", sess.Sealed)
		fmt.Printf("Runs:         %d\n", len(sess.Runs))

		for i, id := range sess.Runs {
			r, err := session.LoadRun(kvDir, id)
			if err != nil {
				fmt.Printf("  Run %d: %s (error loading)\n", i+1, id)
				continue
			}
			statusStr := "OK"
			if r.ExitCode != 0 {
				statusStr = fmt.Sprintf("EXIT %d", r.ExitCode)
			}
			fmt.Printf("  Run %d: [%s] %s  %s  %d metrics  %d claims  %d phases  %d seeds\n",
				i+1, statusStr, strings.Join(r.Command, " "), r.DurationFmt,
				len(r.Metrics), len(r.Claims), len(r.Phases), len(r.Seeds))
		}

		if sess.Sealed {
			seal, err := session.LoadSeal(kvDir)
			if err == nil {
				fmt.Printf("\nSealed at:  %s\n", seal.SealedAt.UTC().Format(time.RFC3339))
				fmt.Printf("Data hash:  %s\n", seal.DataHash)
			}
		}
		return nil
	},
}

var generateClaimsReportPath string

var cmdGenerateClaims = &cobra.Command{
	Use:   "generate-claims --report <report.pdf>",
	Short: "Generate a claims.json template from a signed report",
	Long: `Extracts all final metrics and hardware info from a signed K-Veritas
PDF report and writes a claims.json template. Authors edit this file to
match the values they cite in their paper, then submit it alongside the
report for reviewer cross-referencing.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if generateClaimsReportPath == "" {
			return fmt.Errorf("--report is required")
		}

		meta, err := pdf.ExtractMetadata(generateClaimsReportPath)
		if err != nil {
			return err
		}

		type claimEntry struct {
			Metric    string  `json:"metric"`
			Value     float64 `json:"value"`
			Tolerance float64 `json:"tolerance"`
		}

		type claimsOutput struct {
			Claims []claimEntry `json:"claims"`
		}

		seen := map[string]bool{}
		var claims []claimEntry

		for _, r := range meta.Runs {
			for _, m := range r.Metrics {
				if seen[m.Name] {
					continue
				}
				seen[m.Name] = true
				claims = append(claims, claimEntry{
					Metric:    m.Name,
					Value:     m.Value,
					Tolerance: 1e-4,
				})
			}
		}

		output := claimsOutput{Claims: claims}
		data, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return err
		}

		fmt.Println(string(data))
		return nil
	},
}

func init() {
	cmdGenerateClaims.Flags().StringVar(&generateClaimsReportPath, "report", "", "path to K-Veritas PDF report")
}

// isSourceFile returns true for file arguments that look like executable scripts.
func isSourceFile(path string) bool {
	exts := []string{".py", ".r", ".R", ".jl", ".sh", ".bash", ".rb", ".js", ".ts"}
	lower := strings.ToLower(path)
	for _, ext := range exts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
