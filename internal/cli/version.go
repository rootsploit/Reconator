package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	Version   = "0.1.0"
	BuildDate = "dev"
	GitCommit = "none"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("reconator version %s\n", Version)
		fmt.Printf("  Build date: %s\n", BuildDate)
		fmt.Printf("  Git commit: %s\n", GitCommit)
	},
}
