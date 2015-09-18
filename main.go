package main

import (
	"runtime"

	"github.com/spf13/cobra"

	"github.com/pdxjohnny/cftp/commands"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	var rootCmd = &cobra.Command{Use: "cftp"}
	rootCmd.AddCommand(commands.Commands...)
	rootCmd.Execute()
}
