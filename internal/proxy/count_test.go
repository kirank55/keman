package proxy

import (
	"io"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCountBodyFinishesOnEOF(t *testing.T) {
	var closed atomic.Int32
	var n int64
	b := &countBody{
		ReadCloser: io.NopCloser(strings.NewReader("hello")),
		n:          &n,
		onClose:    func() { closed.Add(1) },
	}
	buf, err := io.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("body %q", buf)
	}
	if closed.Load() != 1 {
		t.Fatalf("onClose after EOF: %d", closed.Load())
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if closed.Load() != 1 {
		t.Fatalf("onClose after Close: %d", closed.Load())
	}
	if n != 5 {
		t.Fatalf("n %d", n)
	}
}

func TestCountBodyFinishesOnCloseWithoutRead(t *testing.T) {
	var closed atomic.Int32
	var n int64
	b := &countBody{
		ReadCloser: io.NopCloser(strings.NewReader("x")),
		n:          &n,
		onClose:    func() { closed.Add(1) },
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if closed.Load() != 1 {
		t.Fatalf("onClose %d", closed.Load())
	}
}
