package gateway

import (
	"context"
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"

	"github.com/boo-admin/gateway/httpext"
	"golang.org/x/exp/slog"
)

func Run() {
	var runner httpext.Runner

	runner.Flags(flag.CommandLine)
	var filename string
	flag.StringVar(&filename, "data-file", "", "数据文件")
	flag.Parse()

	runner.Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))
	srv := NewProxyList(runner.Logger, "gateway")

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
