package gateway

import (
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/boo-admin/boo/errors"
	"github.com/boo-admin/boo/services/authn"
)

type SkipData struct {
	SkipList       []string
	SkipPrefixList []string
}

type SkipPathList struct {
	value atomic.Value
}

func (skiper *SkipPathList) Set(data *SkipData) {
	skiper.value.Store(data)
}

func (skiper *SkipPathList) Get() *SkipData {
	o := skiper.value.Load()
	if o == nil {
		return nil
	}
	data, _ := o.(*SkipData)
	return data
}

func HTTPAuth(skiper *SkipPathList, validateFns ...authn.AuthValidateFunc) func(HandlerFunc) HandlerFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) {
			pa := ctx.Request.URL.Path
			data := skiper.Get()
			if data != nil {
				for _, s := range data.SkipList {
					if s == pa {
						next(ctx)
						return
					}
				}
				for _, s := range data.SkipPrefixList {
					if strings.HasPrefix(pa, s) {
						next(ctx)
						return
					}
				}
			}

			for _, fn := range validateFns {
				stdctx, err := fn(ctx.StdCtx, ctx.Request)
				if err == nil {
					ctx.StdCtx = stdctx
					next(ctx)
					return
				}

				if !errors.Is(err, authn.ErrTokenNotFound) {
					authn.ReturnError(ctx.StdCtx, ctx.ResponseWriter, ctx.Request, http.StatusUnauthorized, err)
					return
				}
			}

			authn.ReturnError(ctx.StdCtx, ctx.ResponseWriter, ctx.Request, http.StatusUnauthorized, authn.ErrTokenNotFound)
		}
	}
}
