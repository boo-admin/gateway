package gateway

import (
	"context"
	"encoding/json"
	"flag"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/boo-admin/boo/errors"
	"github.com/boo-admin/boo/goutils/httpext"
	"github.com/boo-admin/boo/services/authn"
	"github.com/boo-admin/boo/services/authn/jwt_auth"
	"github.com/boo-admin/boo/services/authn/session_auth"
	jwt "github.com/golang-jwt/jwt/v4"
	"golang.org/x/exp/slog"
)

func Run() {
	var runner httpext.Runner
	runner.Flags(flag.CommandLine)

	var jwtAlg string
	var jwtSignKey string
	var jwtVerifyKey string
	flag.StringVar(&jwtAlg, "auth-jwt-alg", "", "jwt 的算法")
	flag.StringVar(&jwtSignKey, "auth-jwt-sign-key", "", "jwt 的签名密码")
	flag.StringVar(&jwtVerifyKey, "auth-jwt-verify-key", "", "jwt 的校验密码")

	var sessionOpt session_auth.Option
	var sessionHash string
	var sessionSecretKey string
	flag.StringVar(&sessionOpt.SessionPath, "auth-session-path", "", "会话的 cookie 路径")
	flag.StringVar(&sessionOpt.SessionKey, "auth-session-key", "", "会话的 cookie 名称")
	flag.StringVar(&sessionHash, "auth-session-hash-method", "", "会话的 hash 算法")
	flag.StringVar(&sessionSecretKey, "auth-session-secret-key", "", "会话的 hash 算法的加密 key")

	var filename string
	flag.StringVar(&filename, "data-file", "", "数据文件")

	flag.Parse()

	jwtConfig := jwt_auth.NewJWTAuth(jwtAlg, []byte(jwtSignKey), []byte(jwtVerifyKey))

	if h, err := session_auth.GetHash(sessionHash); err != nil {
		runner.Logger.Warn("参数 'session-hash-method' 的值是未知的 hash 算法", slog.Any("method", sessionHash))
		os.Exit(10002)
		return
	} else {
		sessionOpt.SessionHash = h
	}
	sessionOpt.SecretKey = []byte(sessionSecretKey)

	runner.Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))
	srv := NewProxyList(runner.Logger, "gateway")

	jwtUser := func(ctx context.Context, req *http.Request, token *jwt.Token) (context.Context, error) {
		claims, ok := token.Claims.(*jwt.StandardClaims)
		if !ok {
			return nil, errors.New("claims not jwt.StandardClaims")
		}

		ss := strings.SplitN(claims.Audience, " ", 2)
		if len(ss) < 2 {
			return nil, errors.New("Audience '" + claims.Audience + "' is invalid")
		}
		// userid := ss[0]
		username := ss[1]

		req.Header.Set("X-HW-AuthKey", username)
		return authn.ContextWithReadCurrentUser(ctx, authn.ReadCurrentUserFunc(func(ctx context.Context) (authn.AuthUser, error) {
			return authn.NewMockUser(username), nil
		})), nil
	}

	sessionUser := func(ctx context.Context, req *http.Request, values url.Values) (context.Context, error) {
		username := values.Get(session_auth.SESSION_USER_KEY)
		req.Header.Set("X-HW-AuthKey", username)
		return authn.ContextWithReadCurrentUser(ctx, authn.ReadCurrentUserFunc(func(ctx context.Context) (authn.AuthUser, error) {
			return authn.NewMockUser(username), nil
		})), nil
	}

	authFuncs := []authn.AuthValidateFunc{
		jwt_auth.TokenVerify(
			[]jwt_auth.TokenFindFunc{
				jwt_auth.TokenFromQuery,
			},
			[]jwt_auth.TokenCheckFunc{
				jwt_auth.JWTCheck(jwtConfig, jwtUser),
			}),
		session_auth.SessionVerify(&sessionOpt, sessionUser),
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
