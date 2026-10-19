package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var cmdShell = &cobra.Command{
	Use:   "shell",
	Short: "Open a recorded terminal: every command becomes a run",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("kveritas shell needs Linux or macOS; on Windows use: kveritas run -- <command>")
	},
}
