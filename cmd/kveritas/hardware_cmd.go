package main

import (
	"fmt"

	"github.com/Mamadou2727/kveritas-go/internal/hardware"
	"github.com/spf13/cobra"
)

var hardwareJSON bool

var cmdHardware = &cobra.Command{
	Use:   "hardware",
	Short: "Show the CPU, memory and GPUs K-Veritas detects",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		inv := hardware.Detect()
		if hardwareJSON {
			return printJSON(inv)
		}
		fmt.Printf("OS:      %s/%s\n", inv.OS, inv.Arch)
		fmt.Printf("CPU:     %s, %d cores\n", inv.CPUModel, inv.CPUCores)
		fmt.Printf("Memory:  %.1f GB\n", inv.MemGB)
		if len(inv.GPUs) == 0 {
			fmt.Println("GPUs:    none detected")
			return nil
		}
		fmt.Printf("CUDA:    %s\n", inv.CUDAVersion)
		for _, g := range inv.GPUs {
			fmt.Printf("GPU %d:   %s, %.0f MB, driver %s\n", g.Index, g.Name, g.MemoryMB, g.Driver)
		}
		return nil
	},
}

func init() {
	cmdHardware.Flags().BoolVar(&hardwareJSON, "json", false, "print as JSON")
}
