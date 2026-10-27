package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/client"
	"github.com/Mamadou2727/kveritas-go/internal/crypto"
	"github.com/Mamadou2727/kveritas-go/internal/session"
	"github.com/Mamadou2727/kveritas-go/internal/signer"
	"github.com/spf13/cobra"
)

type signerDoc struct {
	SelfReported bool              `json:"self_reported,omitempty"`
	Signed       bool              `json:"signed"`
	History      *signer.Statement `json:"history,omitempty"`
}

var keyServer string

func shortFP(fp string) string {
	return fp[:min(16, len(fp))]
}

func printUnsealed(list []signer.Unsealed) {
	if len(list) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "[kveritas] %s open on your other linked machines; your reports list them:\n", plural(len(list), "unsealed session"))
	for _, u := range list[:min(len(list), 5)] {
		fmt.Fprintf(os.Stderr, "[kveritas]   %s  started %s, %s\n", u.Session, shortTime(u.StartedAt), plural(u.Runs, "run"))
	}
}

func shortTime(at string) string {
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return at
	}
	return t.Local().Format("2006-01-02 15:04")
}

func sealProof(sess *session.Session, dataHash string) (*client.SignerProof, error) {
	key, err := signer.Load()
	if err != nil {
		if sess.Signer != "" {
			return nil, fmt.Errorf("this session was started with signer key %s, which cannot be loaded: %w", shortFP(sess.Signer), err)
		}
		return nil, nil
	}
	if sess.Signer != "" && key.Fingerprint() != sess.Signer {
		return nil, fmt.Errorf("this session was started with signer key %s; this machine's key is %s", shortFP(sess.Signer), shortFP(key.Fingerprint()))
	}
	return &client.SignerProof{PublicKey: key.Public(), Signature: key.Sign(signer.SealMessage(sess.ID, dataHash))}, nil
}

func localSignerHistory(sess *session.Session, dataHash string) *session.SignerHistory {
	key, err := signer.Load()
	if err != nil {
		return nil
	}
	st, err := signer.LocalStatement(key, sess.ID, dataHash)
	if err != nil {
		return nil
	}
	_ = signer.RecordLocal(key, "seal", sess.ID)
	return &session.SignerHistory{Statement: st, SelfReported: true}
}

func renderSignerHistory(seal *session.SealRecord, jr *verifyDoc) {
	sh := seal.SignerHistory
	if sh == nil {
		fmt.Fprintf(out, "Signer:     none (covers this session only; other sessions by this author are not counted)\n")
		return
	}
	var st signer.Statement
	if json.Unmarshal([]byte(sh.Statement), &st) != nil {
		fmt.Fprintf(out, "Signer:     history unreadable\n")
		return
	}
	bound := st.DataHash == seal.DataHash && st.SessionID == seal.SessionID
	byKV := !sh.SelfReported && bound && crypto.HistorySigned(sh.Statement, st.At, sh.Signature)
	signed := byKV || (!sh.SelfReported && bound && anchorSigned(sh))
	if jr != nil {
		jr.Signer = &signerDoc{SelfReported: sh.SelfReported, Signed: signed, History: &st}
	}
	switch {
	case sh.SelfReported:
		fmt.Fprintf(out, "Signer:     key %s, history self-reported (offline, not confirmed)\n", shortFP(st.Signer))
	case !signed:
		fmt.Fprintf(out, "Signer:     history signature INVALID\n")
		return
	case byKV:
		fmt.Fprintf(out, "Signer:     key %s, first seen %s, history signed by K-Veritas\n", shortFP(st.Signer), shortTime(st.FirstSeen))
	default:
		fmt.Fprintf(out, "Signer:     key %s, first seen %s, history signed by the given key\n", shortFP(st.Signer), shortTime(st.FirstSeen))
	}
	fmt.Fprintf(out, "Sessions:   %d started, %d sealed, %d abandoned, %d never sealed", st.Started, st.Sealed, st.Abandoned, st.Open)
	if st.Keys > 1 {
		fmt.Fprintf(out, " (%d linked keys)", st.Keys)
	}
	fmt.Fprintln(out)
	if st.Started <= 1 {
		fmt.Fprintf(out, "            New signer: no earlier history, other attempts cannot be ruled out.\n")
	}
	for _, u := range st.Unsealed[:min(len(st.Unsealed), 10)] {
		status := "never sealed"
		if u.Status == "abandoned" {
			status = "abandoned"
		}
		fmt.Fprintf(out, "  %s  started %s, %s, %s\n", u.Session, shortTime(u.StartedAt), plural(u.Runs, "run"), status)
	}
	if n := len(st.Unsealed) - 10; n > 0 {
		fmt.Fprintf(out, "  and %d more\n", n)
	}
}

func anchorSigned(sh *session.SignerHistory) bool {
	if verifyKeyPath == "" {
		return false
	}
	data, err := os.ReadFile(verifyKeyPath)
	if err != nil {
		return false
	}
	key, err := crypto.LoadPublicKey(data)
	return err == nil && crypto.VerifyPSS(key, crypto.HistoryPayload(sh.Statement), sh.Signature) == nil
}

func localOpen(key *signer.Key) string {
	if key == nil {
		return ""
	}
	if open := signer.LocalOpen(key); len(open) > 0 {
		return open[len(open)-1][:min(8, len(open[len(open)-1]))]
	}
	return ""
}

func cleanSession(kvDir string) error {
	sess, err := session.Load(kvDir)
	if err != nil || sess.Sealed || sess.Signer == "" {
		return nil
	}
	key, err := signer.Load()
	if err != nil || key.Fingerprint() != sess.Signer {
		return nil
	}
	if sess.ServerURL == "local" {
		return signer.RecordLocal(key, "clean", sess.ID)
	}
	c := client.New(sess.ServerURL)
	c.HTTPClient.Timeout = 10 * time.Second
	if err := c.Clean(sess.ID, key); err != nil {
		return fmt.Errorf("could not remove the session from the server (%v); nothing was deleted, try again", serverRefusal(err))
	}
	return nil
}

func cleanByID(id string) error {
	key, err := signer.Load()
	if err != nil {
		return err
	}
	if len(id) >= 8 {
		for _, open := range signer.LocalOpen(key) {
			if strings.HasPrefix(open, id) {
				if err := signer.RecordLocal(key, "clean", open); err != nil {
					return err
				}
				fmt.Printf("Session %s removed.\n", id)
				return nil
			}
		}
	}
	if err := client.New(keyServer).Clean(id, key); err != nil {
		return serverRefusal(err)
	}
	fmt.Printf("Session %s removed. Delete its .kveritas folder if it still exists.\n", id)
	return nil
}

var cmdAbandon = &cobra.Command{
	Use:   "abandon [session-id]",
	Short: "Drop a session: it is removed here and listed as abandoned in your later reports",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key, err := signer.Load()
		if err != nil {
			return err
		}
		if len(args) == 1 {
			if err := client.New(keyServer).Abandon(args[0], key); err != nil {
				return serverRefusal(err)
			}
			fmt.Printf("Session %s abandoned.\n", args[0])
			return nil
		}
		kvDir, err := session.Find()
		if err != nil {
			return err
		}
		sess, err := session.Load(kvDir)
		if err != nil {
			return err
		}
		if sess.Signer == "" {
			return fmt.Errorf("this session has no signer key; remove it with 'kveritas clean'")
		}
		if sess.ServerURL == "local" {
			err = signer.RecordLocal(key, "abandon", sess.ID)
		} else {
			err = client.New(sess.ServerURL).Abandon(sess.ID, key)
		}
		if err != nil {
			return serverRefusal(err)
		}
		if err := os.RemoveAll(kvDir); err != nil {
			return err
		}
		fmt.Printf("Session %s abandoned and removed.\n", sess.ID[:8])
		return nil
	},
}

func serverRefusal(err error) error {
	var se *client.ServerError
	if errors.As(err, &se) {
		var body struct {
			Detail string `json:"detail"`
		}
		if json.Unmarshal([]byte(se.Body), &body) == nil && body.Detail != "" {
			return errors.New(body.Detail)
		}
	}
	return err
}

var cmdKey = &cobra.Command{
	Use:   "key",
	Short: "This machine's signer key and the sessions started with it",
	Long: `Every session is registered under this machine's signer key, so a report
lists the sessions you started but never sealed. The key is kept in your
config folder and survives updates. In CI, set KVERITAS_SIGNER_KEY
(see kveritas key export).`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		key, err := signer.Load()
		if err != nil {
			return err
		}
		fmt.Printf("Signer key: %s\n", key.Fingerprint())
		st, err := client.New(keyServer).SignerHistory(key.Fingerprint())
		switch {
		case err != nil:
			fmt.Printf("History:    unavailable (%v)\n", err)
		case st == nil:
			fmt.Println("History:    no sessions yet")
		default:
			fmt.Printf("First seen: %s\n", shortTime(st.FirstSeen))
			fmt.Printf("Sessions:   %d started, %d sealed, %d abandoned, %d never sealed\n", st.Started, st.Sealed, st.Abandoned, st.Open)
			if st.Keys > 1 {
				fmt.Printf("Keys:       %d linked (%d revoked)\n", st.Keys, st.RevokedKeys)
				for _, k := range st.KeyList {
					state := ""
					if k.Revoked {
						state = "  revoked"
					}
					fmt.Printf("  %s  first seen %s%s\n", k.FP, shortTime(k.FirstSeen), state)
				}
			}
			for _, u := range st.Unsealed {
				status := map[string]string{"open": "never sealed"}[u.Status]
				if status == "" {
					status = u.Status
				}
				fmt.Printf("  %s  started %s, %s, %s\n", u.Session, shortTime(u.StartedAt), plural(u.Runs, "run"), status)
			}
		}
		return nil
	},
}

var cmdKeyLink = &cobra.Command{
	Use:   "link [code]",
	Short: "Share one session history across your machines",
	Long: `On the new machine, run kveritas key link to get a code. On a machine
that already has your history, run kveritas key link <code>.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key, err := signer.Load()
		if err != nil {
			return err
		}
		c := client.New(keyServer)
		if len(args) == 0 {
			code, err := c.LinkStart(key)
			if err != nil {
				return serverRefusal(err)
			}
			fmt.Printf("On a machine that already has your history, run:\n  kveritas key link %s\nThe code expires in 10 minutes.\n", code)
			return nil
		}
		st, err := c.LinkConfirm(strings.ToUpper(strings.TrimSpace(args[0])), key)
		if err != nil {
			return serverRefusal(err)
		}
		fmt.Printf("Linked. One history now covers %d keys and %d sessions.\n", st.Keys, st.Started)
		return nil
	},
}

var cmdKeyRevoke = &cobra.Command{
	Use:   "revoke [fingerprint]",
	Short: "Revoke a lost machine's key, or replace this machine's key",
	Long: `With a fingerprint (or its first 16 characters), revoke a linked key, for
example a lost machine. With none, replace this machine's key: the new key
keeps the same history and the old one is revoked. Sessions started with a
revoked key can no longer be sealed.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key, err := signer.Load()
		if err != nil {
			return err
		}
		c := client.New(keyServer)
		if len(args) == 1 {
			st, err := c.SignerHistory(key.Fingerprint())
			if err != nil || st == nil {
				return fmt.Errorf("cannot read this key's history: %v", err)
			}
			target := ""
			for _, k := range st.KeyList {
				if strings.HasPrefix(k.FP, strings.ToLower(args[0])) && len(args[0]) >= 16 {
					target = k.FP
				}
			}
			if target == "" {
				return fmt.Errorf("no linked key starts with %s (see kveritas key)", args[0])
			}
			if err := c.Revoke(target, key); err != nil {
				return serverRefusal(err)
			}
			fmt.Printf("Key %s revoked.\n", shortFP(target))
			return nil
		}
		if os.Getenv(signer.EnvKey) != "" {
			return fmt.Errorf("the key comes from %s; replace it on a machine with a key file and update the secret", signer.EnvKey)
		}
		next, err := signer.New()
		if err != nil {
			return err
		}
		code, err := c.LinkStart(next)
		if err != nil {
			return serverRefusal(err)
		}
		if _, err := c.LinkConfirm(code, key); err != nil {
			return serverRefusal(err)
		}
		if err := next.Save(); err != nil {
			return err
		}
		if err := c.Revoke(key.Fingerprint(), next); err != nil {
			return fmt.Errorf("new key saved and linked, but revoking the old one failed: %w", serverRefusal(err))
		}
		fmt.Printf("New key %s keeps your history; old key %s is revoked.\n", shortFP(next.Fingerprint()), shortFP(key.Fingerprint()))
		return nil
	},
}

var cmdKeyExport = &cobra.Command{
	Use:   "export",
	Short: "Print this machine's signer key, to set as KVERITAS_SIGNER_KEY in CI",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		key, err := signer.Load()
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Keep this secret: anyone holding it can start and seal sessions as you.\n")
		fmt.Println(key.Export())
		return nil
	},
}

func init() {
	for _, c := range []*cobra.Command{cmdKey, cmdAbandon, cmdClean} {
		c.PersistentFlags().StringVar(&keyServer, "server", defaultServer, "attestation server URL")
	}
	cmdKey.AddCommand(cmdKeyLink, cmdKeyRevoke, cmdKeyExport)
}
