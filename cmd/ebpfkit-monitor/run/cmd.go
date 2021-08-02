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
	"github.com/Gui774ume/ebpfkit-monitor/pkg/model"
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
	Short: "graph generates a graphviz representation of the ELF file",
	Long:  "graph generates a graphviz representation of the ELF file",
	RunE:  graphCmd,
}

var start = &cobra.Command{
	Use:   "start",
	Short: "start monitoring the bpf syscall at runtime",
	Long:  "start monitoring the bpf syscall at runtime and look for malicious behavior",
	RunE:  startCmd,
}

var options model.EBPFKitOptions

func init() {
	EBPFKitMonitor.PersistentFlags().StringVarP(
		&options.EBPFAssetPath,
		"asset",
		"a",
		"",
		"path to the eBPF asset (ELF format expected)")

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
	_ = prog.MarkPersistentFlagRequired("asset")

	m.Flags().StringVarP(
		&options.Section,
		"section",
		"s",
		"",
		"map section to dump")
	_ = m.MarkPersistentFlagRequired("asset")

	start.Flags().StringArrayVar(
		&options.AllowedProcesses,
		"allowed-processes",
		[]string{},
		"defines the list of binary paths which processes are allowed to use the bpf syscall. Each path will be truncated past its first 350 characters. When this parameter is not set, any process can use the bpf syscall.",
	)

	EBPFKitMonitor.AddCommand(prog)
	EBPFKitMonitor.AddCommand(m)
	EBPFKitMonitor.AddCommand(report)
	EBPFKitMonitor.AddCommand(graph)
	EBPFKitMonitor.AddCommand(start)
}
