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
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/Gui774ume/ebpfkit-monitor/pkg/monitor"
)

func progCmd(cmd *cobra.Command, args []string) error {
	mon, err := monitor.NewMonitor(options.EBPFAssetPath)
	if err != nil {
		logrus.Fatalf("failed to run ebpfkit-monitor: %v", err)
	}
	if err := mon.ShowProgram(options.Section, options.Dump, options.Helper, options.Map); err != nil {
		logrus.Fatalf("failed to run ebpfkit-monitor: %v", err)
	}
	return nil
}

func mapCmd(cmd *cobra.Command, args []string) error {
	mon, err := monitor.NewMonitor(options.EBPFAssetPath)
	if err != nil {
		logrus.Fatalf("failed to run ebpfkit-monitor: %v", err)
	}
	if err := mon.ShowMap(options.Section); err != nil {
		logrus.Fatalf("failed to run ebpfkit-monitor: %v", err)
	}
	return nil
}

func reportCmd(cmd *cobra.Command, args []string) error {
	mon, err := monitor.NewMonitor(options.EBPFAssetPath)
	if err != nil {
		logrus.Fatalf("failed to run ebpfkit-monitor: %v", err)
	}
	if err := mon.ShowReport(); err != nil {
		logrus.Fatalf("failed to run ebpfkit-monitor: %v", err)
	}
	return nil
}

func graphCmd(cmd *cobra.Command, args []string) error {
	mon, err := monitor.NewMonitor(options.EBPFAssetPath)
	if err != nil {
		logrus.Fatalf("failed to run ebpfkit-monitor: %v", err)
	}
	if err := mon.GenerateGraph(options.EBPFAssetPath); err != nil {
		logrus.Fatalf("failed to run ebpfkit-monitor: %v", err)
	}
	return nil
}
