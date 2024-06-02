package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/boo-admin/gateway/httprouter"
	"golang.org/x/exp/slog"
)

func NewProxyList(logger *slog.Logger, name string) *ProxyList {
	pl := &ProxyList{
		logger:      logger,
		myname:      name,
		handlerList: &HandlerList{},
	}
	pl.handlerList.initRouter = pl.init
	pl.handlerList.rebuildWithoutLocked()

	return pl
}

type ProxyList struct {
	logger      *slog.Logger
	myname      string
	handlerList *HandlerList
}

func (pl *ProxyList) Use(middleware func(next HandlerFunc) HandlerFunc) {
	pl.handlerList.Use(middleware)
}

func (pl *ProxyList) OnChanged(fn func(map[string]*Service)) {
	pl.handlerList.OnChanged(fn)
}

func (pl *ProxyList) Set(svcList map[string]*Service) {
	pl.handlerList.Set(svcList)
}

func (pl *ProxyList) init(router *httprouter.Router) {
	router.Handle("/proxylist", func(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
		switch req.Method {
		case http.MethodGet:
			pl.list(req.Context(), w, req)
			return
			// case http.MethodPost:
			// 	pl.attach(req.Context(), w, req)
			// 	return
		}

		http.Error(w,
			http.StatusText(http.StatusMethodNotAllowed),
			http.StatusMethodNotAllowed,
		)
	})
	router.Handle("/proxylist/:uuid", func(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
		uuid := params.ByName("uuid")

		switch req.Method {
		// case http.MethodGet:
		// 	pl.list(req.Context(), w, req)
		// 	return
		case http.MethodPost:
			pl.attach(req.Context(), uuid, w, req)
			return
		case http.MethodPut:
			pl.attach(req.Context(), uuid, w, req)
			return
		case http.MethodDelete:
			pl.detach(req.Context(), uuid, w, req)
			return
		}

		http.Error(w,
			http.StatusText(http.StatusMethodNotAllowed),
			http.StatusMethodNotAllowed,
		)
	})

	router.NotFound = http.HandlerFunc(pl.NotFound)
}

func (pl *ProxyList) NotFound(w http.ResponseWriter, req *http.Request) {
	http.NotFound(w, req)
}

func (pl *ProxyList) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	router := pl.handlerList.getRouter()
	if router == nil {
		http.NotFound(w, req)
		return
	}
	router.ServeHTTP(w, req)
}

func (pl *ProxyList) list(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var result = pl.handlerList.ListServices()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(result)
	if err != nil {
		pl.logger.Warn("[ProxyList] write failure while list service info", slog.Any("error", err))
	}
}

func (pl *ProxyList) heartbeat(ctx context.Context, uuid string, w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r.Body != nil {
			io.Copy(ioutil.Discard, r.Body)
			r.Body.Close()
		}
	}()

	ok := pl.handlerList.Heartbeat(uuid, time.Now())
	if ok {
		pl.logger.Info("[ProxyList] service '" + uuid + "' heartbeat successful")
	} else {
		pl.logger.Warn("[ProxyList] service '" + uuid + "' heartbeat successful, but service alread exists")
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, err := io.WriteString(w, "OK")
	if err != nil {
		pl.logger.Warn("[ProxyList] write failure while heartbeat service info", slog.Any("error", err))
	}
}

func (pl *ProxyList) attach(ctx context.Context, uuid string, w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r.Body != nil {
			io.Copy(ioutil.Discard, r.Body)
			r.Body.Close()
		}
	}()

	if strings.Contains(uuid, "/") {
		pl.logger.Warn("[ProxyList] attach service fail, uuid invalid - '" + uuid + "'")
		http.Error(w, "uuid invalid - '"+uuid+"'", http.StatusBadRequest)
		return
	}

	var info Service
	err := json.NewDecoder(r.Body).Decode(&info)
	if err != nil {
		pl.logger.Warn("[ProxyList] attach service fail", slog.Any("error", err))
		http.Error(w, "read params fail: "+err.Error(), http.StatusBadRequest)
		return
	}

	_, err = url.Parse(info.BaseURL)
	if err != nil {
		pl.logger.Warn("[ProxyList] attach service fail, parse base url fail", slog.Any("error", err))
		http.Error(w, "parse 'url' fail: "+err.Error(), http.StatusBadRequest)
		return
	}

	created := pl.handlerList.Attach(uuid, &info)
	if created {
		pl.logger.Info("[ProxyList] service '" + uuid + "' attach successful")
	} else {
		pl.logger.Warn("[ProxyList] service '" + uuid + "' attach successful, but service alread exists")
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, err = io.WriteString(w, "OK")
	if err != nil {
		pl.logger.Warn("[ProxyList] write failure while attach service info", slog.Any("error", err))
	}
}

func (pl *ProxyList) detach(ctx context.Context, uuid string, w http.ResponseWriter, r *http.Request) {
	if r.Body != nil {
		io.Copy(ioutil.Discard, r.Body)
		r.Body.Close()
	}

	deleted := pl.handlerList.Detach(uuid)
	if deleted {
		pl.logger.Info("[ProxyList] service '" + uuid + "' detach successful")
	} else {
		pl.logger.Warn("[ProxyList] service '" + uuid + "' detach, but service not found")
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, err := io.WriteString(w, "OK")
	if err != nil {
		pl.logger.Warn("[ProxyList] write failure while attach service info", slog.Any("error", err))
	}
}

type Client struct {
	Client  *http.Client
	BaseURL string
}

func (c *Client) List(ctx context.Context) ([]Service, error) {
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}

	response, err := client.Get(c.BaseURL)
	if err != nil {
		return nil, err
	}
	defer func() {
		if response.Body != nil {
			io.Copy(ioutil.Discard, response.Body)
			response.Body.Close()
		}
	}()
	if response.StatusCode != http.StatusOK {
		return nil, toResponseError(response, "list service info")
	}

	var result []Service
	err = json.NewDecoder(response.Body).Decode(&result)
	return result, err
}

func (c *Client) Heartbeat(ctx context.Context, uuid string) error {
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}

	response, err := client.Post(urljoin(c.BaseURL, uuid+"/heartbeat"),
		"text/plain", strings.NewReader("ok"))
	if err != nil {
		return err
	}
	defer func() {
		if response.Body != nil {
			io.Copy(ioutil.Discard, response.Body)
			response.Body.Close()
		}
	}()
	if response.StatusCode != http.StatusOK {
		return toResponseError(response, "send heartbeat message")
	}
	return nil
}

func (c *Client) Attach(ctx context.Context, svc Service) error {
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}

	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(svc)
	if err != nil {
		return errors.New("register myself failure，encode service info fail," + err.Error())
	}

	fmt.Println(urljoin(c.BaseURL, svc.UUID))

	response, err := client.Post(urljoin(c.BaseURL, svc.UUID),
		"application/json", &buf)
	if err != nil {
		return errors.New("register myself failure, " + err.Error())
	}
	defer func() {
		if response.Body != nil {
			io.Copy(ioutil.Discard, response.Body)
			response.Body.Close()
		}
	}()
	if response.StatusCode != http.StatusOK {
		return toResponseError(response, "register myself failure")
	}
	return nil
}

func (c *Client) Detach(ctx context.Context, uuid string) error {
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequest(http.MethodDelete, urljoin(c.BaseURL, uuid), strings.NewReader(""))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if response.Body != nil {
			io.Copy(ioutil.Discard, response.Body)
			response.Body.Close()
		}
	}()
	if response.StatusCode != http.StatusOK {
		return toResponseError(response, "unregister myself failure")
	}
	return nil
}

func toResponseError(response *http.Response, msg string) error {
	var sb strings.Builder

	sb.WriteString(msg)
	sb.WriteString(", ")
	sb.WriteString(response.Status)
	sb.WriteString(": ")
	io.Copy(&sb, response.Body)
	return errors.New(sb.String())
}

func urljoin(a, b string) string {
	if strings.HasSuffix(a, "/") {
		if strings.HasPrefix(b, "/") {
			return a + b[1:]
		}
		return a + b
	}
	if strings.HasPrefix(b, "/") {
		return a + b
	}
	return a + "/" + b
}
