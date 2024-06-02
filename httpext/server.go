package httpext

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type TcpKeepAliveListener struct {
	KeepAlivePeriod time.Duration
	*net.TCPListener
}

func (ln TcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(ln.KeepAlivePeriod)
	return tc, nil
}

func IsSocketBindError(err error) bool {
	errOpError, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	errSyscallError, ok := errOpError.Err.(*os.SyscallError)
	if !ok {
		return false
	}
	errErrno, ok := errSyscallError.Err.(syscall.Errno)
	if !ok {
		return false
	}
	if errErrno == syscall.EADDRINUSE {
		return true
	}
	const WSAEADDRINUSE = 10048
	if runtime.GOOS == "windows" && errErrno == WSAEADDRINUSE {
		return true
	}
	return false
}

func ListenAtDynamicPort(network, address string, portStart, portEnd int) (string, net.Listener, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", nil, err
	}
	ln, err := net.Listen(network, address)
	if err == nil {
		return address, ln, nil
	}

	var lasterr = err
	for i := portStart; i <= portEnd; i++ {
		listenAt := net.JoinHostPort(host, strconv.Itoa(i))
		ln, err = net.Listen(network, listenAt)
		if err == nil {
			return listenAt, ln, nil
		}
		if !IsSocketBindError(err) {
			return "", nil, err
		}
		lasterr = err
	}
	if lasterr != nil {
		return "", nil, lasterr
	}
	return "", nil, errors.New("bind address fail")
}

func ParseTlsVersion(s string) (uint16, error) {
	switch s {
	case "tls10":
		return tls.VersionTLS10, nil
	case "tls11":
		return tls.VersionTLS11, nil
	case "tls12":
		return tls.VersionTLS12, nil
	case "tls13":
		return tls.VersionTLS13, nil
	default:
		return 0, errors.New("tls version '" + s + "' is invalid")
	}
}

// type HTTPConfig struct {
// 	ListenAt string
// 	Network  string
// 	EnableTcpKeepAlive bool

// 	CertFile  string
// 	KeyFile    string
// 	MinTlsVersion string
// 	MaxTlsVersion string
// 	CipherSuites string
// }

// func RunServer(cfg Config, handler http.Handler) error {
// 	srv := &http.Server{Addr: cfg.ListenAt, Handler: handler}

// 	if cfg.EnableHTTPS {
// 		if cfg.MinTlsVersion != "" {
// 			version, err := ParseTlsVersion(cfg.MinTlsVersion)
// 			if err != nil {
// 				return errors.New("min tls version '"+cfg.MinTlsVersion+"' is invalid")
// 				return
// 			}
// 			if srv.TLSConfig == nil {
// 				srv.TLSConfig = &tls.Config{}
// 			}
// 			srv.TLSConfig.MinVersion = version
// 		}

// 		if cfg.MaxTlsVersion != "" {
// 			version, err := ParseTlsVersion(cfg.MaxTlsVersion)
// 			if err != nil {
// 				return errors.New("max tls version '"+cfg.MaxTlsVersion+"' is invalid")
// 			}
// 			if srv.TLSConfig == nil {
// 				srv.TLSConfig = &tls.Config{}
// 			}
// 			srv.TLSConfig.MaxVersion = version
// 		}

// 		if cfg.CipherSuites != "" {
// 			if srv.TLSConfig == nil {
// 				srv.TLSConfig = &tls.Config{}
// 			}
// 			SetCipherSuites(srv.TLSConfig, cipherSuites)
// 		}
// 	}
// 	ln, err := net.Listen(cfg.Network, cfg.ListenAt)
// 	if err != nil {
// 		return err
// 	}
// 	defer ln.Close()

// 	if cfg.EnableTcpKeepAlive {
// 		tcpListener, ok := ln.(*net.TCPListener)
// 		if ok {
// 			ln = TcpKeepAliveListener{tcpListener}
// 		}
// 	}

// 	if len(wrapFn) > 0 {
// 		ln = wrapFn[0](ln)
// 	}

// 	if cfg.EnableHTTPS {
// 		return srv.ServeTLS(ln, cfg.CertFile, cfg.KeyFile)
// 	}
// 	return srv.Serve(ln)
// }
