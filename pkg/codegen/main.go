package main

import (
	"os"

	v1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	controllergen "github.com/rancher/wrangler/pkg/controller-gen"
	"github.com/rancher/wrangler/pkg/controller-gen/args"
)

func main() {
	os.Unsetenv("GOPATH")
	controllergen.Run(args.Options{
		OutputPackage: "github.com/rancher/tunnelware/pkg/generated",
		Boilerplate:   "scripts/boilerplate.go.txt",
		Groups: map[string]args.Group{
			"cert-manager.io": {
				Types: []interface{}{
					v1.Certificate{},
				},
				GenerateTypes: true,
			},
		},
	})
}
