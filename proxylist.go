package gateway

import (
	"context"
	"encoding/json"
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
	router.Handle("/proxylist", func(ctx *Context) {
		switch ctx.Request.Method {
		case http.MethodGet:
			pl.list(ctx.StdCtx, ctx.ResponseWriter, ctx.Request)
			return
			// case http.MethodPost:
			// 	pl.attach(ctx.Request.Context(), w, ctx.Request)
			// 	return
		}

		http.Error(ctx.ResponseWriter,
			http.StatusText(http.StatusMethodNotAllowed),
			http.StatusMethodNotAllowed,
		)
	})
	router.Handle("/proxylist/:uuid", func(ctx *Context) {
		uuid := ctx.Params.ByName("uuid")

		switch ctx.Request.Method {
		// case http.MethodGet:
		// 	pl.list(ctx.StdCtx, ctx.ResponseWriter, ctx.Request)
		// 	return
		case http.MethodPost:
			pl.attach(ctx.StdCtx, uuid, ctx.ResponseWriter, ctx.Request)
			return
		case http.MethodPut:
			pl.attach(ctx.StdCtx, uuid, ctx.ResponseWriter, ctx.Request)
			return
		case http.MethodDelete:
			pl.detach(ctx.StdCtx, uuid, ctx.ResponseWriter, ctx.Request)
			return
		}

		http.Error(ctx.ResponseWriter,
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
