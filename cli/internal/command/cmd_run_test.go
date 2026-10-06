package command

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCommandProcess(t *testing.T) {
	if os.Getenv("SEC_TEST_RUN_COMMAND") != "1" {
		return
	}
	os.Exit(Run(runProcessArgs()))
}

func TestRunChildArgsProcess(t *testing.T) {
	if os.Getenv("SEC_TEST_RUN_COMMAND") != "1" {
		return
	}
	fmt.Fprintln(os.Stdout, strings.Join(runProcessArgs(), " "))
	os.Exit(0)
}

func runProcessArgs() []string {
	for i, arg := range os.Args {
		if arg == "--" {
			return os.Args[i+1:]
		}
	}
	return nil
}

func runCommandProcess(t *testing.T, args ...string) (int, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, append([]string{"-test.run=^TestRunCommandProcess$", "--"}, args...)...)
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "SEC_TEST_RUN_COMMAND=1", "SEC_NO_USAGE=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return exit.ExitCode(), string(out)
	}
	t.Fatal(err)
	return -1, ""
}

func TestRunHelpWithoutStore(t *testing.T) {
	t.Setenv("SEC_STORE", filepath.Join(t.TempDir(), "missing", "store.enc"))
	t.Setenv("SEC_KEY", strings.Repeat("ab", 32))
	for _, args := range [][]string{
		{"run", "--help"},
		{"run", "-h"},
		{"run", "demo", "--help"},
		{"run", "--help", "--"},
		{"run", "--help", "--", "missing-command"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			code, out := runCommandProcess(t, args...)
			if code != 0 || !strings.Contains(out, "Usage of run:") || !strings.Contains(out, "-file") || !strings.Contains(out, "-only") {
				t.Fatalf("code=%d, output=%q", code, out)
			}
		})
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"run", "demo"}, "нужен разделитель --"},
		{[]string{"run", "demo", "--"}, "нет команды после --"},
	} {
		code, out := runCommandProcess(t, tc.args...)
		if code != 2 || !strings.Contains(out, tc.want) {
			t.Fatalf("%v: code=%d, output=%q", tc.args, code, out)
		}
	}
}

func TestRunForwardsChildHelpFlags(t *testing.T) {
	testStore(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	code, out := runCommandProcess(t, "run", "demo", "--", exe, "-test.run=^TestRunChildArgsProcess$", "--", "--help", "-h", "--json")
	if code != 0 || out != "--help -h --json\n" {
		t.Fatalf("code=%d, output=%q", code, out)
	}
}
