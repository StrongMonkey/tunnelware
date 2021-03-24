package cmd

import (
	cli "github.com/rancher/wrangler-cli"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	root := cli.Command(&App{}, cobra.Command{
		Long: "Creating tunnel for your local server",
	})
	root.AddCommand(
		NewServerCommand(),
		NewClientCommand(),
	)
	return root
}

type App struct {
}

func (a *App) Run(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}
