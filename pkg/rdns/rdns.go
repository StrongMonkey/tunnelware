package rdns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
)

func GetDomain(ctx context.Context, client *Client, hosts []string, cname bool) (string, error) {
	if err := ensureDomainExists(ctx, client, hosts, cname); err != nil {
		return "", err
	}

	return client.RenewDomain()
}

func ensureDomainExists(ctx context.Context, client *Client, hosts []string, cname bool) error {
	domain, err := client.GetDomain(cname)
	if err != nil && strings.Contains(err.Error(), "forbidden to use") {
		// intentional fall through
	} else if err != nil || domain != nil {
		return err
	}

	if _, err := client.CreateDomain(hosts, cname); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	wait.JitterUntil(func() {
		domain, err = client.GetDomain(cname)
		if err != nil {
			logrus.Debug("failed to get domain")
		}
	}, time.Second, 1.3, true, ctx.Done())

	if domain == nil {
		return fmt.Errorf("failed to create domain")
	}

	return nil
}
