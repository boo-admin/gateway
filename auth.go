package gateway

import (
	"net/http"

	"github.com/boo-admin/boo/services/authn"
	"github.com/boo-admin/boo/errors"
)

func HTTPAuth(validateFns ...authn.AuthValidateFunc) func(HandlerFunc) HandlerFunc {
	return func(next HandlerFunc) HandlerFunc {
		hfn := func(ctx *Context) {
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
			return
		}
		return HandlerFunc(hfn)
	}
}
