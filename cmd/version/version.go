package version

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"go.miloapis.com/auth-provider-zitadel/pkg/version"
)

// NewVersionCommand creates the version subcommand
func NewVersionCommand() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long:  "Print version information for auth-provider-zitadel",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVersion(output)
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "text", "Output format (text, json)")

	return cmd
}

func runVersion(output string) error {
	versionInfo := version.Get()

	switch output {
	case "json":
		data, err := json.MarshalIndent(versionInfo, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal version info: %w", err)
		}
		fmt.Println(string(data))
	case "text":
		fmt.Println(versionInfo.String())
	default:
		return fmt.Errorf("unsupported output format: %s", output)
	}

	return nil
}
