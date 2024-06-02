package gateway

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/boo-admin/gateway/httprouter"
)

type ServicePath struct {
	Path       string `json:"path,omitempty"`
	TrimPrefix bool   `json:"trim_prefix,omitempty"`
}

type Service struct {
	UUID      string `json:"uuid,omitempty"`
	BaseURL   string `json:"url,omitempty"`
	Heartbeat bool   `json:"heartbeat,omitempty"`

	CreatedAt   time.Time `json:"created_at,omitempty"`
	HeartbeatAt time.Time `json:"heartbeat_at,omitempty"`

	Paths []ServicePath `json:"paths,omitempty"`
}

type HandlerFunc func(ctx context.Context, w http.ResponseWriter, r *http.Request)

type HandlerList struct {
	// router *httprouter.Router
	router atomic.Uintptr

	lock     sync.Mutex
	services map[string]*Service
	onChange func(map[string]*Service)

	initRouter func(router *httprouter.Router)

	middlewares []func(next HandlerFunc) HandlerFunc
}

func (hl *HandlerList) Use(middleware func(next HandlerFunc) HandlerFunc) {
	hl.middlewares = append(hl.middlewares, middleware)
}

func (hl *HandlerList) setRouter(router *httprouter.Router) {
	hl.router.Store(uintptr(unsafe.Pointer(router)))
}

func (hl *HandlerList) getRouter() *httprouter.Router {
	o := hl.router.Load()
	if o == 0 {
		return nil
	}
	return (*httprouter.Router)(unsafe.Pointer(o))
}

func (hl *HandlerList) Heartbeat(name string, t time.Time) bool {
	hl.lock.Lock()
	defer hl.lock.Unlock()
	if len(hl.services) == 0 {
		return false
	}

	svc, ok := hl.services[name]
	if !ok {
		return false
	}
	svc.HeartbeatAt = t
	return true
}

func (hl *HandlerList) Attach(name string, handler *Service) bool {
	hl.lock.Lock()
	defer hl.lock.Unlock()

	if hl.services == nil {
		hl.services = map[string]*Service{}
	}

	old, created := hl.services[name]
	if created {
		handler.CreatedAt = old.CreatedAt
	}
	hl.services[name] = handler

	hl.rebuildWithoutLocked()
	if hl.onChange != nil {
		hl.onChange(hl.services)
	}
	return !created
}

func (hl *HandlerList) Detach(name string) bool {
	hl.lock.Lock()
	defer hl.lock.Unlock()

	if len(hl.services) == 0 {
		return false
	}

	_, ok := hl.services[name]
	if !ok {
		return false
	}
	delete(hl.services, name)

	hl.rebuildWithoutLocked()
	if hl.onChange != nil {
		hl.onChange(hl.services)
	}
	return true
}

func (hl *HandlerList) ListServices() []Service {
	hl.lock.Lock()
	defer hl.lock.Unlock()

	var result []Service
	for _, svc := range hl.services {
		result = append(result, *svc)
	}
	return result
}

func (hl *HandlerList) Set(svcList map[string]*Service) {
	hl.lock.Lock()
	defer hl.lock.Unlock()
	if hl.services == nil {
		hl.services = map[string]*Service{}
	}

	for key, svc := range svcList {
		hl.services[key] = svc
	}

	hl.rebuildWithoutLocked()
}

func (hl *HandlerList) OnChanged(fn func(map[string]*Service)) {
	hl.onChange = fn
}

func (hl *HandlerList) rebuildWithoutLocked() {
	var router = httprouter.New()
	hl.initRouter(router)

	for _, svc := range hl.services {
		target, err := url.Parse(svc.BaseURL)
		if err != nil {
			panic(err)
		}

		var handler = httputil.NewSingleHostReverseProxy(target)
		var handlerFunc = func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
			handler.ServeHTTP(w, r)
		}

		for _, pa := range svc.Paths {
			if pa.TrimPrefix {
				router.Handle(urljoin(pa.Path, "/*filepath"), func(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
					r.URL.Path = params.ByName("filepath")
					for _, middleware := range hl.middlewares {
						handlerFunc = middleware(handlerFunc)
					}
					handlerFunc(r.Context(), w, r)
				})
			} else {
				router.Handle(urljoin(pa.Path, "/*filepath"), func(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
					for _, middleware := range hl.middlewares {
						handlerFunc = middleware(handlerFunc)
					}
					handlerFunc(r.Context(), w, r)
				})
			}
		}
	}

	hl.setRouter(router)
}