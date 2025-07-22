package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"go.miloapis.com/auth-provider-zitadel/cmd/actionsserver"
	"go.miloapis.com/auth-provider-zitadel/cmd/controller"
	"go.miloapis.com/auth-provider-zitadel/cmd/version"
	"go.miloapis.com/auth-provider-zitadel/internal/config"
)

var (
	globalConfig = &config.GlobalConfig{}
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "auth-provider-zitadel",
	Short: "Kubernetes auth provider for Zitadel",
	Long: `A Kubernetes operator that provides authentication and authorization
capabilities using Zitadel as the identity provider.

This tool can run in multiple modes:
- controller: Run the Kubernetes controller manager
- version: Print version information`,
}

func main() {
	if err := execute(); err != nil {
		os.Exit(1)
	}
}

// execute adds all child commands to the root command and sets flags appropriately.
func execute() error {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().BoolVar(&globalConfig.Development, "development", false, "Enable development mode")
	rootCmd.PersistentFlags().StringVar(&globalConfig.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&globalConfig.LogFormat, "log-format", "json", "Log format (json, console)")

	// Add subcommands
	rootCmd.AddCommand(controller.NewControllerCommand(globalConfig))
	rootCmd.AddCommand(version.NewVersionCommand())
	rootCmd.AddCommand(actionsserver.NewActionsServerCommand(globalConfig))

	return rootCmd.Execute()
}

// initConfig reads in config file and ENV variables if set
func initConfig() {
	if err := config.InitializeLogging(globalConfig); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing logging: %v\n", err)
		os.Exit(1)
	}
}
