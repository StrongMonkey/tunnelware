package cmd

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/rancher/remotedialer"
	"github.com/rancher/tunnelware/pkg/rdns"
	cli "github.com/rancher/wrangler-cli"
	"github.com/rancher/wrangler/pkg/ticker"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func NewClientCommand() *cobra.Command {
	client := cli.Command(&Client{}, cobra.Command{
		Short: "Run tunnel client",
		Example: "  tunnelware client http 8080",
	})
	return client
}

type Client struct {
	Server string `name:"server" usage:"Address to connect to" default:"wss://tunnelware.do.rancher.space/connect"`
	Debug  bool   `name:"debug" usage:"Enable debug"`
}

func (c *Client) Run(cmd *cobra.Command, args []string) error {
	if len(args) != 2 {
		return errors.New("require at least one argument")
	}
	if c.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	homedir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Join(homedir, ".tunnelware"), 0755); err != nil {
		return err
	}

	u, err := url.Parse(c.Server)
	if err != nil {
		return err
	}

	rdnsClient := rdns.NewClient()

	domain, err := rdns.GetDomain(cmd.Context(), rdnsClient, []string{u.Hostname()}, net.ParseIP(u.Hostname()) == nil)
	if err != nil {
		return err
	}
	go func() {
		for range ticker.Context(cmd.Context(), time.Hour * 6) {
			if _, err := rdnsClient.RenewDomain(); err != nil {
				logrus.Error(err)
			}
		}
	}()

	clientID := strings.Split(domain, ".")[0]

	headers := http.Header{
		"X-Tunnel-ID": []string{clientID},
	}

	query := u.Query()
	query.Add("fqdn", domain)
	scheme := args[0]
	host := args[1]
	if !strings.Contains(host, ":") {
		host = fmt.Sprintf("%v://127.0.0.1:%v", scheme, host)
	} else {
		host = fmt.Sprintf("%v://%v", scheme, host)
	}
	query.Add("forward", host)
	u.RawQuery = query.Encode()

	logrus.Debugf("connecting to %v", u.String())

	go func() {
		fmt.Printf("http://%v --------> %v\nhttps://%v -------> %v\n", domain, host, domain, host)
		remotedialer.ClientConnect(cmd.Context(), u.String(), headers, nil, func(string, string) bool { return true }, nil)
	}()
	<- cmd.Context().Done()
	return nil
}
