package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

const releasesBaseURL = "https://github.com/27-GROUP/kveritas-releases/raw/main/bin"

var cmdUpdate = &cobra.Command{
	Use:   "update",
	Short: "Update kveritas to the latest version",
	Long: `Downloads the latest kveritas binary for your OS and architecture
from the official release channel, and replaces the current executable.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		goos := runtime.GOOS
		goarch := runtime.GOARCH

		binaryName := fmt.Sprintf("kveritas-%s-%s", goos, goarch)
		if goos == "windows" {
			binaryName += ".exe"
		}

		url := fmt.Sprintf("%s/%s", releasesBaseURL, binaryName)

		execPath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("cannot determine executable path: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Downloading %s ...\n", url)

		resp, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("download failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("download failed: server returned %d", resp.StatusCode)
		}

		tmpPath := execPath + ".update"
		tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			return fmt.Errorf("cannot write update file: %w", err)
		}

		n, err := io.Copy(tmpFile, resp.Body)
		tmpFile.Close()
		if err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("download interrupted: %w", err)
		}

		if n < 1024 {
			os.Remove(tmpPath)
			return fmt.Errorf("downloaded file too small (%d bytes); binary may not be available for %s/%s", n, goos, goarch)
		}

		if err := os.Rename(tmpPath, execPath); err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("cannot replace binary: %w\nTry running with sudo or move %s to %s manually.", err, tmpPath, execPath)
		}

		fmt.Fprintf(os.Stderr, "Updated successfully (%d bytes written to %s)\n", n, execPath)
		return nil
	},
}
