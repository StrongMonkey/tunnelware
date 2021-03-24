//go:generate go run pkg/codegen/cleanup/main.go
//go:generate /bin/rm -rf pkg/generated
//go:generate go run pkg/codegen/main.go

package main

import (
	"github.com/rancher/tunnelware/pkg/cmd"
	_ "github.com/rancher/tunnelware/pkg/generated/controllers/cert-manager.io"
	cli "github.com/rancher/wrangler-cli"
	_ "github.com/rancher/wrangler/pkg/generated/controllers/networking.k8s.io"
)

var (
	Version   = "v0.0.0-dev"
	GitCommit = "HEAD"
)

func main() {
	cli.Main(cmd.New())
}
