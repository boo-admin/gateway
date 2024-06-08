// Copyright 2013 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

// Package httprouter is a trie based high performance HTTP request router.
//
// A trivial example is:
//
//	package main
//
//	import (
//	    "fmt"
//	    "github.com/julienschmidt/httprouter"
//	    "net/http"
//	    "log"
//	)
//
//	func Index(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
//	    fmt.Fprint(w, "Welcome!\n")
//	}
//
//	func Hello(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
//	    fmt.Fprintf(w, "hello, %s!\n", ps.ByName("name"))
//	}
//
//	func main() {
//	    router := httprouter.New()
//	    router.GET("/", Index)
//	    router.GET("/hello/:name", Hello)
//
//	    log.Fatal(http.ListenAndServe(":8080", router))
//	}
//
// The router matches incoming requests by the request method and the path.
// If a handle is registered for this path and method, the router delegates the
// request to that function.
// For the methods GET, POST, PUT, PATCH, DELETE and OPTIONS shortcut functions exist to
// register handles, for all other methods router.Handle can be used.
//
// The registered path, against which the router matches incoming requests, can
// contain two types of parameters:
//
//	Syntax    Type
//	:name     named parameter
//	*name     catch-all parameter
//
// Named parameters are dynamic path segments. They match anything until the
// next '/' or the path end:
//
//	Path: /blog/:category/:post
//
//	Requests:
//	 /blog/go/request-routers            match: category="go", post="request-routers"
//	 /blog/go/request-routers/           no match, but the router would redirect
//	 /blog/go/                           no match
//	 /blog/go/request-routers/comments   no match
//
// Catch-all parameters match anything until the path end, including the
// directory index (the '/' before the catch-all). Since they match anything
// until the end, catch-all parameters must always be the final path element.
//
//	Path: /files/*filepath
//
//	Requests:
//	 /files/                             match: filepath="/"
//	 /files/LICENSE                      match: filepath="/LICENSE"
//	 /files/templates/article.html       match: filepath="/templates/article.html"
//	 /files                              no match, but the router would redirect
//
// The value of parameters is saved as a slice of the Param struct, consisting
// each of a key and a value. The slice is passed to the Handle func as a third
// parameter.
// There are two ways to retrieve the value of a parameter:
//
//	// by the name of the parameter
//	user := ps.ByName("user") // defined by :user or *user
//
//	// by the index of the parameter. This way you can also get the name (key)
//	thirdKey   := ps[2].Key   // the name of the 3rd parameter
//	thirdValue := ps[2].Value // the value of the 3rd parameter
package httprouter

import (
	"net/http"

	// "strings"
	"sync"
)

// MatchedRoutePathParam is the Param name under which the path of the matched
// route is stored, if Router.SaveMatchedRoutePath is set.
var MatchedRoutePathParam = "$matchedRoutePath"

// Router is a http.Handler which can be used to dispatch requests to different
// handler functions via configurable routes
type Router struct {
	trees *node

	ctxPool   sync.Pool
	maxParams uint16

	// UseRawPath if enabled, the url.RawPath will be used to find parameters.
	UseRawPath bool

	// UnescapePathValues if true, the path value will be unescaped.
	// If UseRawPath is false (by default), the UnescapePathValues effectively is true,
	// as url.Path gonna be used, which is already unescaped.
	UnescapePathValues bool

	// RemoveExtraSlash a parameter can be parsed from the URL even with extra slashes.
	// See the PR #1817 and issue #1644
	RemoveExtraSlash bool

	// If enabled, adds the matched route path onto the http.Request context
	// before invoking the handler.
	// The matched route path is only added to handlers of routes that were
	// registered when this option was enabled.
	SaveMatchedRoutePath bool

	// Enables automatic redirection if the current route can't be matched but a
	// handler for the path with (without) the trailing slash exists.
	// For example if /foo/ is requested but a route only exists for /foo, the
	// client is redirected to /foo with http status code 301 for GET requests
	// and 308 for all other request methods.
	RedirectTrailingSlash bool

	// If enabled, the router tries to fix the current request path, if no
	// handle is registered for it.
	// First superfluous path elements like ../ or // are removed.
	// Afterwards the router does a case-insensitive lookup of the cleaned path.
	// If a handle can be found for this route, the router makes a redirection
	// to the corrected path with status code 301 for GET requests and 308 for
	// all other request methods.
	// For example /FOO and /..//Foo could be redirected to /foo.
	// RedirectTrailingSlash is independent of this option.
	RedirectFixedPath bool

	// Configurable http.Handler which is called when no matching route is
	// found. If it is not set, http.NotFound is used.
	NotFound http.Handler

	// Function to handle panics recovered from http handlers.
	// It should be used to generate a error page and return the http error code
	// 500 (Internal Server Error).
	// The handler can be used to keep your server from crashing because of
	// unrecovered panics.
	PanicHandler func(http.ResponseWriter, *http.Request, interface{})
}

// Make sure the Router conforms with the http.Handler interface
var _ http.Handler = New()

// New returns a new initialized Router.
// Path auto-correction, including trailing slashes, is enabled by default.
func New() *Router {
	r := &Router{
		RedirectTrailingSlash: true,
		RedirectFixedPath:     true,
	}

	r.ctxPool.New = func() interface{} {
		ctx := &Context{}
		ctx.skippedNodes = make([]skippedNode, 0, r.maxParams)
		ctx.Params = make(Params, 0, r.maxParams)
		return ctx
	}
	return r
}

func (r *Router) getCtx() *Context {
	ctx, _ := r.ctxPool.Get().(*Context)
	ctx.Params = ctx.Params[0:0]             // reset slice
	ctx.skippedNodes = ctx.skippedNodes[0:0] // reset slice
	return ctx
}

func (r *Router) putCtx(ctx *Context) {
	if ctx != nil {
		ctx.StdCtx = nil
		ctx.Request = nil
		ctx.ResponseWriter = nil
		r.ctxPool.Put(ctx)
	}
}

func (r *Router) saveMatchedRoutePath(path string, handle HandleFunc) HandleFunc {
	return func(ctx *Context) {
		ctx.Params = append(ctx.Params, Param{Key: MatchedRoutePathParam, Value: path})
		handle(ctx)
	}
}

// // GET is a shortcut for router.Handle(http.MethodGet, path, handle)
// func (r *Router) GET(path string, handle Handle) {
// 	r.Handle(http.MethodGet, path, handle)
// }

// // HEAD is a shortcut for router.Handle(http.MethodHead, path, handle)
// func (r *Router) HEAD(path string, handle Handle) {
// 	r.Handle(http.MethodHead, path, handle)
// }

// // OPTIONS is a shortcut for router.Handle(http.MethodOptions, path, handle)
// func (r *Router) OPTIONS(path string, handle Handle) {
// 	r.Handle(http.MethodOptions, path, handle)
// }

// // POST is a shortcut for router.Handle(http.MethodPost, path, handle)
// func (r *Router) POST(path string, handle Handle) {
// 	r.Handle(http.MethodPost, path, handle)
// }

// // PUT is a shortcut for router.Handle(http.MethodPut, path, handle)
// func (r *Router) PUT(path string, handle Handle) {
// 	r.Handle(http.MethodPut, path, handle)
// }

// // PATCH is a shortcut for router.Handle(http.MethodPatch, path, handle)
// func (r *Router) PATCH(path string, handle Handle) {
// 	r.Handle(http.MethodPatch, path, handle)
// }

// // DELETE is a shortcut for router.Handle(http.MethodDelete, path, handle)
// func (r *Router) DELETE(path string, handle Handle) {
// 	r.Handle(http.MethodDelete, path, handle)
// }

// Handle registers a new request handle with the given path and method.
//
// For GET, POST, PUT, PATCH and DELETE requests the respective shortcut
// functions can be used.
//
// This function is intended for bulk loading and to allow the usage of less
// frequently used, non-standardized or custom methods (e.g. for internal
// communication with a proxy).
func (r *Router) Handle(path string, handle HandleFunc) {
	varsCount := uint16(0)

	// if method == "" {
	// 	panic("method must not be empty")
	// }
	if len(path) < 1 || path[0] != '/' {
		panic("path must begin with '/' in path '" + path + "'")
	}
	if handle == nil {
		panic("handle must not be nil")
	}

	if r.SaveMatchedRoutePath {
		varsCount++
		handle = r.saveMatchedRoutePath(path, handle)
	}

	if r.trees == nil {
		r.trees = new(node)
	}

	root := r.trees
	// if root == nil {
	// 	root = new(node)
	// 	r.trees[method] = root
	// }

	root.addRoute(path, handle)

	// Update maxParams
	if paramsCount := countParams(path); paramsCount+varsCount > r.maxParams {
		r.maxParams = paramsCount + varsCount
	}
}

// ServeFiles serves files from the given file system root.
// The path must end with "/*filepath", files are then served from the local
// path /defined/root/dir/*filepath.
// For example if root is "/etc" and *filepath is "passwd", the local file
// "/etc/passwd" would be served.
// Internally a http.FileServer is used, therefore http.NotFound is used instead
// of the Router's NotFound handler.
// To use the operating system's file system implementation,
// use http.Dir:
//
//	router.ServeFiles("/src/*filepath", http.Dir("/var/www"))
func (r *Router) ServeFiles(path string, root http.FileSystem) {
	if len(path) < 10 || path[len(path)-10:] != "/*filepath" {
		panic("path must end with /*filepath in path '" + path + "'")
	}

	fileServer := http.FileServer(root)

	r.Handle(path, func(ctx *Context) {
		ctx.Request.URL.Path = ctx.Params.ByName("filepath")
		fileServer.ServeHTTP(ctx.ResponseWriter, ctx.Request)
	})
}

func (r *Router) recv(w http.ResponseWriter, req *http.Request) {
	if rcv := recover(); rcv != nil {
		r.PanicHandler(w, req, rcv)
	}
}

// Lookup allows the manual lookup of a method + path combo.
// This is e.g. useful to build a framework around this router.
// If the path was found, it returns the handle function and the path parameter
// values. Otherwise the third return value indicates whether a redirection to
// the same path with an extra / without the trailing slash should be performed.
func (r *Router) Lookup(path string) (HandleFunc, Params, bool) {
	if root := r.trees; root != nil {
		ctx := r.getCtx()

		value := root.getValue(path, &ctx.Params, &ctx.skippedNodes, false)
		if value.handle == nil {
			r.putCtx(ctx)
			return nil, nil, value.tsr
		}
		if len(ctx.Params) == 0 {
			return value.handle, nil, value.tsr
		}
		return value.handle, ctx.Params, value.tsr
	}
	return nil, nil, false
}

// ServeHTTP makes the router implement the http.Handler interface.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if r.PanicHandler != nil {
		defer r.recv(w, req)
	}

	rPath := req.URL.Path
	unescape := false
	if r.UseRawPath && len(req.URL.RawPath) > 0 {
		rPath = req.URL.RawPath
		unescape = r.UnescapePathValues
	}

	if r.RemoveExtraSlash {
		rPath = CleanPath(rPath)
	}

	if root := r.trees; root != nil {

		ctx := r.getCtx()
		ctx.ResponseWriter = w
		ctx.Request = req

		if value := root.getValue(rPath, &ctx.Params, &ctx.skippedNodes, unescape); value.handle != nil {
			value.handle(ctx)
			r.putCtx(ctx)
			return
		} else if req.Method != http.MethodConnect && rPath != "/" {
			// Moved Permanently, request with GET method
			code := http.StatusMovedPermanently
			if req.Method != http.MethodGet {
				// Permanent Redirect, request with same method
				code = http.StatusPermanentRedirect
			}

			if value.tsr && r.RedirectTrailingSlash {
				if len(rPath) > 1 && rPath[len(rPath)-1] == '/' {
					req.URL.Path = rPath[:len(rPath)-1]
				} else {
					req.URL.Path = rPath + "/"
				}
				http.Redirect(w, req, req.URL.String(), code)
				return
			}

			// Try to fix the request path
			if r.RedirectFixedPath {
				fixedPath, found := root.findCaseInsensitivePath(
					CleanPath(rPath),
					r.RedirectTrailingSlash,
				)
				if found {
					req.URL.Path = string(fixedPath)
					http.Redirect(w, req, req.URL.String(), code)
					return
				}
			}
		}
	}

	// Handle 404
	if r.NotFound != nil {
		r.NotFound.ServeHTTP(w, req)
	} else {
		http.NotFound(w, req)
	}
}
