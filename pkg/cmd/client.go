package cmd

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/browser"
	"github.com/pkg/errors"
	"github.com/rancher/remotedialer"
	cli "github.com/rancher/wrangler-cli"
	"github.com/rancher/wrangler/pkg/randomtoken"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	domain = "tunnelware.do.rancher.space"
)

type Claim struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func NewClientCommand() *cobra.Command {
	client := cli.Command(&Client{}, cobra.Command{
		Short:   "Run tunnel client",
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

	tokenFile := filepath.Join(homedir, ".tunnelware", "token")
	if _, err := os.Stat(filepath.Join(homedir, ".tunnelware", "token")); err != nil {
		// request auth token
		state, err := randomtoken.Generate()
		if err != nil {
			return err
		}

		serverURL, err := url.Parse(c.Server)
		if err != nil {
			return err
		}

		url := fmt.Sprintf("https://%s/login/github?state=%s", serverURL.Host, state)
		fmt.Printf("Redirecting to %v for github login\n", url)
		// credit from https://github.com/hashicorp/terraform/pull/24107/files
		// Windows Subsystem for Linux (bash for Windows) doesn't have xdg-open available
		// but you can execute cmd.exe from there; try to identify it
		if !hasProgram("xdg-open") && hasProgram("cmd.exe") {
			r := strings.NewReplacer("&", "^&")
			if out, err := exec.Command("cmd.exe", "/c", "start", r.Replace(url)).Output(); err != nil {
				return errors.Wrap(err, string(out))
			}
		} else {
			if err := browser.OpenURL(url); err != nil {
				return err
			}
		}

		for {
			resp, err := http.Get(fmt.Sprintf("https://%s/jwt/%s", serverURL.Host, state))
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			if resp.StatusCode == 503 {
				continue
			}
			token, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			if err := ioutil.WriteFile(tokenFile, token, 0755); err != nil {
				return err
			}
			break
		}
	}

	token, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		return err
	}

	claim := &Claim{}
	if _, err := jwt.ParseWithClaims(string(token), claim, nil); err != nil {
		if err.(*jwt.ValidationError).Errors != jwt.ValidationErrorUnverifiable {
			return err
		}
	}

	u, err := url.Parse(c.Server)
	if err != nil {
		return err
	}
	scheme := args[0]
	forwardHost := args[1]
	// if only contains number, then use 127.0.0.1
	if govalidator.IsNumeric(forwardHost) {
		forwardHost = fmt.Sprintf("%v://127.0.0.1:%v", scheme, forwardHost)
	} else {
		forwardHost = fmt.Sprintf("%v://%v", scheme, forwardHost)
	}

	headers := http.Header{
		"X-TUNNEL-ID":   []string{fmt.Sprintf("%s:%s", strings.ToLower(claim.Username), forwardHost)},
		"Authorization": []string{"Bearer " + string(token)},
	}

	logrus.Debugf("connecting to %v", u.String())
	domainWithUsername := fmt.Sprintf("%s.%s", strings.ToLower(claim.Username), domain)
	go func() {
		fmt.Printf("http://%v --------> %v\nhttps://%v -------> %v\n", domainWithUsername, forwardHost, domainWithUsername, forwardHost)
		for {
			remotedialer.ClientConnect(cmd.Context(), u.String(), headers, nil, func(string, string) bool { return true }, nil)
			time.Sleep(time.Second * 5)
		}
	}()
	<-cmd.Context().Done()
	return nil
}

func hasProgram(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
