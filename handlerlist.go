package gateway

import (
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/boo-admin/gateway/httprouter"
	"github.com/boo-admin/boo/client/registry"
)

type ServicePath = registry.ServicePath
type Service = registry.Service

type Context = httprouter.Context
type HandlerFunc = httprouter.HandleFunc

type HandlerList struct {
	// router *httprouter.Router
	router atomic.Uintptr

	skiper SkipPathList

	lock     sync.Mutex
	services map[string]*Service
	onChange func(map[string]*Service)

	initRouter func(router *httprouter.Router)

	middlewares []func(next HandlerFunc) HandlerFunc
}

func (hl *HandlerList) GetAuthSkipPathList() *SkipPathList {
	return &hl.skiper
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


	var skipData SkipData
	for _, svc := range hl.services {
		target, err := url.Parse(svc.BaseURL)
		if err != nil {
			panic(err)
		}

		var handler = httputil.NewSingleHostReverseProxy(target)
		// handler.Rewrite = func(r *ProxyRequest) {
		// 	r.Out.Host = r.In.Host // if desired
		// }

		var handlerFunc = func(ctx *Context) {
			handler.ServeHTTP(ctx.ResponseWriter, ctx.Request)
		}

		for _, pa := range svc.SkipLoginPaths {
			if strings.HasSuffix(pa, "*") {
				skipData.SkipPrefixList = append(skipData.SkipPrefixList, strings.TrimSuffix(pa, "*"))
			} else {
				skipData.SkipList = append(skipData.SkipList, pa)
			}
		}

		for _, pa := range svc.Paths {
			if pa.TrimPrefix {
				router.Handle(urljoin(pa.Path, "/*filepath"), func(ctx *Context) {
					ctx.Request.URL.Path = ctx.Params.ByName("filepath")
					for _, middleware := range hl.middlewares {
						handlerFunc = middleware(handlerFunc)
					}
					handlerFunc(ctx)
				})
			} else {
				router.Handle(urljoin(pa.Path, "/*filepath"), func(ctx *Context) {
					for _, middleware := range hl.middlewares {
						handlerFunc = middleware(handlerFunc)
					}
					handlerFunc(ctx)
				})
			}
		}
	}

	hl.skiper.Set(&skipData)
	hl.setRouter(router)
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
