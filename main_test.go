package gateway

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/boo-admin/gateway/httpext"
	"golang.org/x/exp/slog"
)

type TestServer struct {
	Runner    httpext.Runner
	Logger    *slog.Logger
	ProxyList *ProxyList
}

func (server *TestServer) Start() error {
	server.Runner.Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))
	server.ProxyList = NewProxyList(server.Runner.Logger, "gateway")

	return server.Runner.Start(context.Background(), server.ProxyList)
}

func (server *TestServer) Stop() error {
	return server.Runner.Stop(context.Background())
}

func TestSimple(t *testing.T) {
	testhttp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	defer testhttp.Close()

	var srv TestServer
	if err := srv.Start(); err != nil {
		t.Error(err)
		return
	}

	defer func() {
		if err := srv.Stop(); err != nil {
			t.Error(err)
			return
		}
	}()

	response, err := http.Get(srv.Runner.MustURL())
	if err != nil {
		t.Error(err)
		return
	}
	assertResponse(t, response, http.StatusNotFound, "404 page not found")

	client := Client{
		BaseURL: srv.Runner.MustURL() + "/proxylist",
	}

	err = client.Attach(context.Background(), Service{

		UUID:      "test",
		BaseURL:   testhttp.URL,
		Heartbeat: false,

		Paths: []ServicePath{
			{
				Path:       "/test",
				TrimPrefix: false,
			},
		},
	})
	if err != nil {
		t.Error(err)
		return
	}

	response, err = http.Get(srv.Runner.MustURL() + "/test/abc")
	if err != nil {
		t.Error(err)
		return
	}
	assertResponse(t, response, http.StatusOK, "hello")

	err = client.Detach(context.Background(), "test")
	if err != nil {
		t.Error(err)
		return
	}

	response, err = http.Get(srv.Runner.MustURL() + "/test/abc")
	if err != nil {
		t.Error(err)
		return
	}
	assertResponse(t, response, http.StatusNotFound, "404 page not found")
}

func assertResponse(t testing.TB, response *http.Response, status int, body string) {
	if response.StatusCode != status {
		t.Error("want", status, "got", response.StatusCode)
		return
	}

	bs, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
		return
	}
	bs = bytes.TrimSpace(bs)

	if string(bs) != body {
		t.Error("want", body, "got", string(bs))
		return
	}
}
