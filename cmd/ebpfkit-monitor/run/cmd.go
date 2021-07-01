/*
Copyright © 2020 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package run

import (
	"github.com/spf13/cobra"
)

// EBPFKitMonitor represents the base command of ebpfkit-monitor
var EBPFKitMonitor = &cobra.Command{
	Use: "ebpfkit-monitor",
}

var prog = &cobra.Command{
	Use:   "prog",
	Short: "prints information about one or multiple programs",
	Long:  "prints information about one or multiple programs from the provided ELF file",
	RunE:  progCmd,
}

var m = &cobra.Command{
	Use:   "map",
	Short: "prints information about one or multiple maps",
	Long:  "prints information about one or multiple maps from the provided ELF file",
	RunE:  mapCmd,
}

var report = &cobra.Command{
	Use:   "report",
	Short: "prints summarized information about the maps and programs",
	Long:  "prints summarized information about the maps and programs in the provided ELF file",
	RunE:  reportCmd,
}

var graph = &cobra.Command{
	Use:   "graph",
	Short: "graph generates a .dot graph",
	Long:  "graph generates a .dot graph representing all the programs in the provided ELF file",
	RunE:  graphCmd,
}

type EBPFKitOptions struct {
	EBPFAssetPath string
	Section       string
	Helper        string
	Map           string
	Dump          bool
}

var options EBPFKitOptions

func init() {
	EBPFKitMonitor.PersistentFlags().StringVarP(
		&options.EBPFAssetPath,
		"asset",
		"a",
		"",
		"path to the eBPF asset (ELF format expected)")
	_ = EBPFKitMonitor.MarkPersistentFlagRequired("asset")

	prog.Flags().StringVarP(
		&options.Section,
		"section",
		"s",
		"",
		"program section to dump")
	prog.Flags().StringVar(
		&options.Helper,
		"helper",
		"",
		"program section eBPF helper selector")
	prog.Flags().StringVar(
		&options.Map,
		"map",
		"",
		"map section selector")
	prog.Flags().BoolVarP(
		&options.Dump,
		"dump",
		"d",
		false,
		"dump the program bytecode")

	m.Flags().StringVarP(
		&options.Section,
		"section",
		"s",
		"",
		"map section to dump")

	EBPFKitMonitor.AddCommand(prog)
	EBPFKitMonitor.AddCommand(m)
	EBPFKitMonitor.AddCommand(report)
	EBPFKitMonitor.AddCommand(graph)
}
