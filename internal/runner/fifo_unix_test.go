//go:build !windows

package runner

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// Far more than a pipe buffer holds, so a reader that stops early leaves the writer
// blocked and the test times out.
func TestOutDrainsLargeOutput(t *testing.T) {
	out, err := openOut()
	if err != nil {
		t.Fatal(err)
	}
	defer out.cleanup()
	const lines = 20000
	go func() {
		w, err := os.OpenFile(out.path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Error(err)
			return
		}
		for i := 0; i < lines; i++ {
			fmt.Fprintf(w, "KV x=%d step=%d\n", i, i)
		}
		w.Close()
		out.finish()
	}()
	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(out.reader)
		done <- string(data)
	}()
	select {
	case data := <-done:
		if n := strings.Count(data, "\n"); n != lines {
			t.Fatalf("read %d lines, want %d", n, lines)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("reader stopped draining the result pipe")
	}
}

func TestOutWaitsForLateWriter(t *testing.T) {
	out, err := openOut()
	if err != nil {
		t.Fatal(err)
	}
	defer out.cleanup()
	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(out.reader)
		done <- string(data)
	}()
	time.Sleep(300 * time.Millisecond)
	w, err := os.OpenFile(out.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(w, "KV x=1")
	w.Close()
	out.finish()
	select {
	case data := <-done:
		if data != "KV x=1\n" {
			t.Fatalf("got %q", data)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no EOF after the last writer closed")
	}
}
