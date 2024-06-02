package httpext

import (
	"context"
	"crypto/tls"
	"flag"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mei-rune/ipfilter"
	"github.com/runner-mei/errors"
	"golang.org/x/exp/slog"
)

var ErrServerInitializing = errors.New("service initializing")
var ErrServerAlreadyStart = errors.New("service already start")
var ErrServerAlreadyStop = errors.New("service already stop")

type Hook interface {
	OnStart(context.Context, *Runner) error
	OnStop(context.Context, *Runner) error
}
type hook struct {
	onStart func(context.Context, *Runner) error
	onStop  func(context.Context, *Runner) error
}

func (h hook) OnStart(ctx context.Context, r *Runner) error {
	if h.onStart == nil {
		return nil
	}

	return h.onStart(ctx, r)
}
func (h hook) OnStop(ctx context.Context, r *Runner) error {
	if h.onStop == nil {
		return nil
	}

	return h.onStop(ctx, r)
}

func MakeHook(onStart, onStop func(context.Context, *Runner) error) Hook {
	return hook{
		onStart: onStart,
		onStop:  onStop,
	}
}

type Runner struct {
	Logger             *slog.Logger
	IPFilterOptions    ipfilter.Options
	Network            string
	ListenAt           string
	EnableTcpKeepAlive bool
	KeepAlivePeriod    time.Duration

	CertFile      string
	KeyFile       string
	MinTlsVersion string
	MaxTlsVersion string
	CipherSuites  string

	CandidatePortStart int
	CandidatePortEnd   int

	lock     sync.Mutex
	srv      *http.Server
	listener net.Listener

	hooks []Hook
}

func (r *Runner) Flags(fs *flag.FlagSet) *flag.FlagSet {
	fs.Func("ipfilter.allow_ips", "允许的 IP 列表（以逗号分隔）", func(s string) error {
		r.IPFilterOptions.AllowedIPs = strings.Split(s, ",")
		return nil
	})
	fs.Func("ipfilter.blocked_ips", "不允许的 IP 列表（以逗号分隔）", func(s string) error {
		r.IPFilterOptions.BlockedIPs = strings.Split(s, ",")
		return nil
	})
	fs.BoolVar(&r.IPFilterOptions.BlockByDefault, "ipfilter.block_default", false, "缺省阻塞所有的IP")
	fs.BoolVar(&r.IPFilterOptions.TrustProxy, "ipfilter.trust_proxy", true, "信任 http 代理传过来的IP")

	fs.StringVar(&r.Network, "network", "https", "")
	fs.StringVar(&r.ListenAt, "listen_at", ":12345", "")
	fs.BoolVar(&r.EnableTcpKeepAlive, "enable_tcpkeepalive", true, "是否启动 tcp 的 keepalive 选项")
	fs.DurationVar(&r.KeepAlivePeriod, "tcpkeepalive_period", 1*time.Minute, "设置 tcp 的 keepalive 的 period 值")
	return fs
}

func (r *Runner) Append(hook Hook) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.hooks = append(r.hooks, hook)
}

func (r *Runner) MustURL(address ...string) string {
	u, err := r.URL()
	if err != nil {
		panic(err)
	}
	return u
}

func (r *Runner) URL(address ...string) (string, error) {
	port, err := r.ListenPort()
	if err != nil {
		return "", err
	}

	var hostAddress = "127.0.0.1"
	if len(address) > 0 {
		if !isZeroAddress(address[0]) {
			hostAddress = address[0]
		}
	}

	network := r.Network
	switch strings.ToLower(network) {
	case "http", "tcp", "":
		network = "http"
	case "https", "tls", "ssl":
		network = "https"
	default:
		return "", errors.New("network '" + network + "' is unsupported")
	}
	return network + "://" + net.JoinHostPort(hostAddress, port), nil
}

func (r *Runner) ListenAddr() (net.Addr, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.srv == nil {
		return nil, ErrServerInitializing
	}
	return r.listener.Addr(), nil
}

func isZeroAddress(addr string) bool {
	return addr == "" ||
		addr == "[::]" ||
		addr == ":" ||
		addr == ":0" ||
		addr == "0.0.0.0:0"
}

func (r *Runner) ListenPort() (string, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.srv == nil {
		return "", ErrServerInitializing
	}

	// if isZeroAddress(r.ListenAt) {
	_, port, err := net.SplitHostPort(r.listener.Addr().String())
	return port, err
	// }
	// _, port, err := net.SplitHostPort(r.ListenAt)
	// return port, err
}

func (r *Runner) Run(ctx context.Context, handler http.Handler) error {
	stopped := make(chan struct{})
	err := r.start(ctx, handler, true, stopped)
	if err != nil {
		return err
	}

	select {
	case <-stopped:
	case <-ctx.Done():
	}

	return r.Stop(ctx)
}

func (r *Runner) Start(ctx context.Context, handler http.Handler) error {
	return r.start(ctx, handler, true, nil)
}

func (r *Runner) start(ctx context.Context, handler http.Handler, isAsync bool, stopped chan struct{}) error {
	if handler == nil {
		return errors.New("handler is missing")
	}
	network := r.Network
	isHTTPs := false

	switch strings.ToLower(network) {
	case "http", "tcp", "":
		network = "tcp"
	case "http+unix", "unix":
		network = "tcp"
	case "https", "tls", "ssl":
		isHTTPs = true
		network = "tcp"
		if r.CertFile == "" || r.KeyFile == "" {
			return errors.New("keyFile or certFile is missing")
		}
	case "https+unix":
		isHTTPs = true
		network = "unix"
		if r.CertFile == "" || r.KeyFile == "" {
			return errors.New("keyFile or certFile is missing")
		}
	default:
		return errors.New("listen: network '" + network + "' is unsupported")
	}

	var srv *http.Server
	var listener net.Listener
	var hooks []Hook

	err := func() error {
		r.lock.Lock()
		defer r.lock.Unlock()

		if r.srv != nil {
			return ErrServerAlreadyStart
		}

		if r.ListenAt == "" {
			r.ListenAt = ":"
		}
		listenAt, ln, err := ListenAtDynamicPort(network, r.ListenAt, r.CandidatePortStart, r.CandidatePortEnd)
		if err != nil {
			return err
		}

		listener = ln
		srv = &http.Server{Addr: listenAt, Handler: handler}

		r.listener = listener
		r.srv = srv

		hooks = make([]Hook, len(r.hooks))
		copy(hooks, r.hooks)
		return nil
	}()
	if err != nil {
		return err
	}

	if isHTTPs {
		if r.MinTlsVersion != "" {
			version, err := ParseTlsVersion(r.MinTlsVersion)
			if err != nil {
				return errors.New("min tls version '" + r.MinTlsVersion + "' is invalid")
			}
			if srv.TLSConfig == nil {
				srv.TLSConfig = &tls.Config{}
			}
			srv.TLSConfig.MinVersion = version
		}

		if r.MaxTlsVersion != "" {
			version, err := ParseTlsVersion(r.MaxTlsVersion)
			if err != nil {
				return errors.New("max tls version '" + r.MaxTlsVersion + "' is invalid")
			}
			if srv.TLSConfig == nil {
				srv.TLSConfig = &tls.Config{}
			}
			srv.TLSConfig.MaxVersion = version
		}

		if r.CipherSuites != "" {
			if srv.TLSConfig == nil {
				srv.TLSConfig = &tls.Config{}
			}
			SetCipherSuites(srv.TLSConfig, r.CipherSuites)
		}
	}

	if tcpListener, ok := listener.(*net.TCPListener); ok {
		if r.KeepAlivePeriod <= 0 {
			r.KeepAlivePeriod = 1 * time.Minute
		}

		listener = TcpKeepAliveListener{
			KeepAlivePeriod: r.KeepAlivePeriod,
			TCPListener:     tcpListener,
		}
	}

	if !r.IPFilterOptions.TrustProxy {
		listener = ipfilter.WrapListener(listener, r.IPFilterOptions, func(addr net.Addr) {
			if r.Logger != nil {
				r.Logger.Info("ip is blocked", slog.Any("addr", addr))
			}
		})
	}

	for idx := range hooks {
		err = hooks[idx].OnStart(ctx, r)
		if err != nil {
			listener.Close()

			for i := 0; i < idx; i++ {
				hooks[i].OnStop(ctx, r)
			}
			return err
		}
	}

	run := func() {
		if stopped != nil {
			defer close(stopped)
		}

		if r.Logger != nil {
			r.Logger.Info("http listen at: " + r.Network + "+" + listener.Addr().String())
		}

		var err error
		if isHTTPs {
			err = srv.ServeTLS(listener, r.CertFile, r.KeyFile)
		} else {
			err = srv.Serve(listener)
		}
		if err != nil {
			if err != http.ErrServerClosed {
				r.Logger.Error("http server start unsuccessful", slog.Any("error", err))
			} else {
				r.Logger.Info("http server stopped")
			}
		}
	}

	if isAsync {
		go run()
	} else {
		run()
	}
	return nil
}

func (r *Runner) Stop(ctx context.Context) error {
	hooks, err := func() ([]Hook, error) {
		r.lock.Lock()
		defer r.lock.Unlock()

		if r.srv == nil {
			return nil, nil
		}

		listenAt := r.listener.Addr().String()

		err1 := r.srv.Close()
		err2 := r.listener.Close()
		if err2 != nil {
			if strings.Contains(err2.Error(), "use of closed network connection") {
				err2 = nil
			}
		}

		r.srv = nil
		r.listener = nil
		if err := errors.Join(err1, err2); err != nil {
			r.Logger.Info("http '" + r.Network + "+" + listenAt + "' is stop failure")
			return nil, err
		}

		r.Logger.Info("http '" + r.Network + "+" + listenAt + "' is stopped")

		hooks := make([]Hook, len(r.hooks))
		copy(hooks, r.hooks)
		return hooks, nil
	}()
	if err != nil {
		return err
	}

	for idx := range hooks {
		err = hooks[idx].OnStop(ctx, r)
		if err != nil {
			return err
		}
	}
	return nil
}
