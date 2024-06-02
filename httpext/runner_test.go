package httpext

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"testing"

	"golang.org/x/exp/slog"
)

func TestRunner(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))

	r := &Runner{
		Logger:             logger,
		Network:            "http",
		ListenAt:           ":34456",
		CandidatePortStart: 50000,
		CandidatePortEnd:   60000,
	}
	net.Listen("tcp", r.ListenAt)

	ctx := context.Background()

	err := r.Start(ctx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	if err != nil {
		t.Error(err)
		return
	}
	defer r.Stop(ctx)

	port, err := r.ListenPort()
	if err != nil {
		t.Error(err)
		return
	}

	if port == "34456" {
		t.Error("want 34456 got", port)
	}

	response, err := http.Get("http://127.0.0.1:" + port)
	if err != nil {
		t.Error(err)
		return
	}

	if response.StatusCode != http.StatusOK {
		t.Error("want ok got", response.Status)
		return
	}

	bs, err := io.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
		return
	}

	if string(bs) != "ok" {
		t.Error("want ok got", string(bs))
	}
}
