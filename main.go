package gateway

import (
	"context"
	"encoding/json"
	"flag"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/boo-admin/boo/errors"
	"github.com/boo-admin/boo/goutils/httpext"
	"github.com/boo-admin/boo/services/authn"
	"github.com/boo-admin/boo/services/authn/boojwt"
	"golang.org/x/exp/slog"
	jwt "github.com/golang-jwt/jwt/v4"
)

func Run() {
	var runner httpext.Runner
	runner.Flags(flag.CommandLine)
	var filename string
	var jwtAlg string
	var jwtSignKey string
	var jwtVerifyKey string
	flag.StringVar(&filename, "data-file", "", "数据文件")
	flag.StringVar(&jwtAlg, "jwt-alg", "", "jwt 的算法")
	flag.StringVar(&jwtSignKey, "jwt-sign-key", "", "jwt 的签名密码")
	flag.StringVar(&jwtVerifyKey, "jwt-verify-key", "", "jwt 的校验密码")
	flag.Parse()

	jwtConfig := boojwt.NewJWTAuth(jwtAlg, []byte(jwtSignKey), []byte(jwtVerifyKey))

	runner.Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))
	srv := NewProxyList(runner.Logger, "gateway")

	loadUser := func(ctx context.Context, req *http.Request, token *jwt.Token) (context.Context, error) {
		claims, ok := token.Claims.(*jwt.StandardClaims)
		if !ok {
			return nil, errors.New("claims not jwt.StandardClaims")
		}

		// ss := strings.SplitN(claims.Audience, " ", 2)
		// if len(ss) < 2 {
		// 	return nil, errors.New("Audience '" + claims.Audience + "' is invalid")
		// }
		// userid := ss[0]
		// username := ss[1]

		req.Header.Set("X-HW-AuthKey", claims.Audience)
		return authn.ContextWithReadCurrentUser(ctx, authn.ReadCurrentUserFunc(func(ctx context.Context) (authn.AuthUser, error) {
			return authn.NewMockUser(claims.Audience), nil
		})), nil
	}

	authFuncs := []authn.AuthValidateFunc{
		boojwt.TokenVerify(
			[]boojwt.TokenFindFunc{
				boojwt.TokenFromQuery,
			},
			[]boojwt.TokenCheckFunc{
				boojwt.JWTCheck(jwtConfig, loadUser),
			}),
	}
	srv.Use(HTTPAuth(srv.GetAuthSkipPathList(), authFuncs...))

	if filename != "" {
		srv.OnChanged(func(data map[string]*Service) {
			bs, err := json.Marshal(data)
			if err != nil {
				runner.Logger.Warn("序列化服务数据失败", slog.Any("error", err))
				return
			}
			err = ioutil.WriteFile(filename, bs, 0666)
			if err != nil {
				runner.Logger.Warn("保存服务数据失败", slog.Any("error", err))
				return
			}
		})

		bs, err := ioutil.ReadFile(filename)
		if err != nil {
			if !os.IsNotExist(err) {
				runner.Logger.Warn("读服务数据失败", slog.Any("error", err))
				os.Exit(10001)
				return
			}
		}
		var svcList map[string]*Service
		err = json.Unmarshal(bs, &svcList)
		if err != nil {
			runner.Logger.Warn("序列化服务数据失败", slog.Any("error", err))
			os.Exit(10002)
			return
		}
		srv.Set(svcList)
	}

	if err := runner.Run(context.Background(), srv); err != nil {
		runner.Logger.Warn("server exit", slog.Any("error", err))
	}
}
