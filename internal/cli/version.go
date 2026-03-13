package cli

import (
	"fmt"

	"github.com/rootsploit/reconator/internal/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("reconator version %s\n", version.Version)
	},
}
