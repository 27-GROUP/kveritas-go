package main

import (
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = ""
)

var versionJSON bool

type versionInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Go      string `json:"go"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

var cmdVersion = &cobra.Command{
	Use:   "version",
	Short: "Show the kveritas version",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		info := versionInfo{Version: version, Commit: commit, Go: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH}
		if versionJSON {
			return printJSON(info)
		}
		build := ""
		if info.Commit != "" {
			build = ", commit " + info.Commit
		}
		fmt.Printf("kveritas %s (%s/%s, %s%s)\n", info.Version, info.OS, info.Arch, info.Go, build)
		return nil
	},
}

func printJSON(v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func init() {
	cmdVersion.Flags().BoolVar(&versionJSON, "json", false, "print as JSON")
}
