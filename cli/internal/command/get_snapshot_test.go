package command

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHelperGetCheckpoint(t *testing.T) {
	if os.Getenv("SEC_TEST_CHECKPOINT") != "1" {
		t.Skip("subprocess only")
	}
	db, err := sql.Open("sqlite", "file:"+os.Getenv("SEC_STORE")+"?mode=rw")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var busy, pages, checkpointed int
	if err := db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &pages, &checkpointed); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%d %d %d", busy, pages, checkpointed)
	os.Exit(0)
}

func requireGetCheckpoint(t *testing.T) {
	t.Helper()
	for i := 0; i < 3; i++ {
		if r := secProc(t, fmt.Sprintf("synthetic-write-%d", i), "set", "app/W"); r.code != 0 {
			t.Fatalf("concurrent set: code %d", r.code)
		}
	}
	// A separate process preserves SQLite's POSIX locks on the get connection.
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperGetCheckpoint$")
	cmd.Env = append(os.Environ(), "SEC_TEST_CHECKPOINT=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "0 0 0" {
		t.Fatalf("get holds a snapshot during external I/O: checkpoint=(%s)", out)
	}
}

type blockingGetWriter struct {
	bytes.Buffer
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockingGetWriter) Write(p []byte) (int, error) {
	w.once.Do(func() {
		close(w.entered)
		<-w.release
	})
	return w.Buffer.Write(p)
}

func TestGetClosesSnapshotBeforeExternalIO(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		clip bool
		want string
	}{
		{"clip", []string{"app/K", "--clip"}, true, "synthetic-current"},
		{"clip-history", []string{"app/K", "--clip", "--prev", "1"}, true, "synthetic-previous"},
		{"clip-ref", []string{"web/L", "--clip"}, true, "synthetic-current"},
		{"clip-inherited", []string{"child/K", "--clip"}, true, "synthetic-current"},
		{"raw", []string{"app/K"}, false, "synthetic-current\n"},
		{"history", []string{"web/L", "--prev", "1"}, false, "synthetic-previous\n"},
		{"peek", []string{"app/K", "--peek"}, false, ""},
		{"binary-peek", []string{"app/B", "--peek"}, false, ""},
		{"fingerprint", []string{"app/K", "--fingerprint"}, false, ""},
		{"json", []string{"web/L", "--json"}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := cliEnv(t)
			for _, v := range []string{"synthetic-previous", "synthetic-current"} {
				if r := secProc(t, v, "set", "app/K"); r.code != 0 {
					t.Fatalf("fixture set: code %d", r.code)
				}
			}
			if r := secProc(t, "", "link", "web/L", "app/K"); r.code != 0 {
				t.Fatalf("fixture link: code %d", r.code)
			}
			if tc.name == "clip-inherited" {
				if r := secProc(t, "", "extend", "child", "--from", "app"); r.code != 0 {
					t.Fatalf("fixture extend: code %d", r.code)
				}
			}
			if tc.name == "binary-peek" {
				p := filepath.Join(dir, "binary-fixture")
				if err := os.WriteFile(p, []byte{0, 1, 2, 3, 255}, 0o600); err != nil {
					t.Fatal(err)
				}
				if r := secProc(t, "", "set", "app/B", "--from-file", p); r.code != 0 {
					t.Fatalf("fixture binary: code %d", r.code)
				}
			}
			w := &blockingGetWriter{entered: make(chan struct{}), release: make(chan struct{})}
			oldOut, oldClip := realStdout, getClipboardWrite
			var output bytes.Buffer
			if tc.clip {
				realStdout = &output
				getClipboardWrite = func(v string) error {
					_, err := w.Write([]byte(v))
					return err
				}
			} else {
				realStdout = w
			}
			done := make(chan int, 1)
			go func() { done <- Run(append([]string{"get"}, tc.args...)) }()
			t.Cleanup(func() {
				close(w.release)
				if code := <-done; code != 0 {
					t.Errorf("get: code %d", code)
				}
				realStdout, stdout, getClipboardWrite, jsonMode = oldOut, oldOut, oldClip, false
				if tc.want != "" && w.String() != tc.want {
					t.Error("materialized value changed")
				}
				if tc.name == "binary-peek" && !strings.Contains(w.String(), "5 байт") {
					t.Error("binary peek lost materialized bytes")
				}
			})
			select {
			case <-w.entered:
			case <-time.After(20 * time.Second):
				t.Fatal("get did not reach blocking mock")
			}
			requireGetCheckpoint(t)
		})
	}
}

func TestGetOnceClipboardContract(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags []string
		fail  bool
		code  int
		gone  bool
	}{
		{"success", []string{"--once", "--clip"}, false, 0, true},
		{"json-success", []string{"--once", "--clip", "--json"}, false, 0, true},
		{"failure", []string{"--once", "--clip"}, true, 2, false},
		{"ordinary-failure", []string{"--clip"}, true, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cliEnv(t)
			if r := secProc(t, "synthetic-once-clipboard", "set", "app/K"); r.code != 0 {
				t.Fatalf("fixture set: code %d", r.code)
			}
			cmd := secCmd("", append([]string{"get", "app/K"}, tc.flags...)...)
			cmd.Args[1] = "-test.run=^TestHelperGetClipboard$"
			cmd.Env = append(cmd.Env, fmt.Sprintf("SEC_TEST_CLIPBOARD_FAIL=%t", tc.fail))
			var out, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &stderr
			code := 0
			if err := cmd.Run(); err != nil {
				if e, ok := err.(*exec.ExitError); ok {
					code = e.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if code != tc.code || !strings.Contains(stderr.String(), "clipboard mock reached") || strings.Contains(out.String()+stderr.String(), "synthetic-once-clipboard") {
				t.Errorf("clipboard contract: code=%d", code)
			}
			r := secProc(t, "", "get", "app/K")
			if tc.gone && r.code != 3 || !tc.gone && (r.code != 0 || r.stdout != "synthetic-once-clipboard\n") {
				t.Errorf("unexpected post-copy key state: code %d", r.code)
			}
		})
	}
}

func TestHelperGetClipboard(t *testing.T) {
	if os.Getenv("SEC_TEST_CLIPBOARD_FAIL") == "" {
		t.Skip("subprocess only")
	}
	getClipboardWrite = func(v string) error {
		if v != "synthetic-once-clipboard" {
			t.Fatal("clipboard received wrong value")
		}
		if r := secProc(t, "", "get", "app/K"); r.code != 0 || strings.TrimSpace(r.stdout) != v {
			t.Fatal("key was removed before clipboard delivery")
		}
		fmt.Fprintln(os.Stderr, "clipboard mock reached")
		if os.Getenv("SEC_TEST_CLIPBOARD_FAIL") == "true" {
			return errors.New("synthetic clipboard failure")
		}
		return nil
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("SEC_TEST_ARGS")), &args); err != nil {
		t.Fatal(err)
	}
	os.Exit(Run(args))
}
