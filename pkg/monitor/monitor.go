/*
Copyright © 2021 GUILLAUME FOURNIER

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

package monitor

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/asm"
	"github.com/DataDog/ebpf/manager"
	"github.com/DataDog/gopsutil/host"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/ebpfkit-monitor/pkg/model"
)

// Monitor is the main Monitor structure
type Monitor struct {
	collectionSpec *ebpf.CollectionSpec
	maxProgLength  int
	maxProgsPerMap int
	bootTime       time.Time
	outputFile     *os.File

	// eBPF helpers
	helperTranslation map[string]asm.BuiltinFunc

	// processes assets
	programTypes   map[ebpf.ProgramType]map[string]int
	programMaps    map[string]map[string]int
	programHelpers map[string]map[asm.BuiltinFunc]int
	helpers        map[asm.BuiltinFunc]map[string]int
	mapTypes       map[ebpf.MapType]map[string]int
	mapPrograms    map[string]map[string]int

	// runtime monitoring
	manager *manager.Manager
	options model.EBPFKitOptions
}

func (m *Monitor) parseAsset(asset string) error {
	if _, err := os.Stat(asset); err != nil {
		return err
	}

	f, err := os.Open(asset)
	if err != nil {
		return err
	}

	m.collectionSpec, err = ebpf.LoadCollectionSpecFromReader(f)
	if err != nil {
		return err
	}
	return nil
}

// NewMonitor returns a new Monitor instance
func NewMonitor(options model.EBPFKitOptions) (*Monitor, error) {
	// Set log level
	logrus.SetLevel(options.LogLevel)

	// Get boot time
	bt, err := host.BootTime()
	if err != nil {
		return nil, err
	}

	m := &Monitor{
		helperTranslation: make(map[string]asm.BuiltinFunc),
		programTypes:      make(map[ebpf.ProgramType]map[string]int),
		programMaps:       make(map[string]map[string]int),
		programHelpers:    make(map[string]map[asm.BuiltinFunc]int),
		helpers:           make(map[asm.BuiltinFunc]map[string]int),
		mapTypes:          make(map[ebpf.MapType]map[string]int),
		mapPrograms:       make(map[string]map[string]int),
		options:           options,
		bootTime:          time.Unix(int64(bt), 0),
	}

	// build eBPF helper translation
	var i int
	var helper asm.BuiltinFunc
	for {
		helper = asm.BuiltinFunc(i)
		if !strings.HasPrefix(helper.String(), "BuiltinFunc") {
			m.helperTranslation[helper.String()] = helper
			i++
		} else {
			break
		}
	}

	// parse asset
	if len(options.EBPFAssetPath) > 0 {
		if err := m.parseAsset(options.EBPFAssetPath); err != nil {
			return nil, errors.Wrapf(err, "couldn't parse asset %s", options.EBPFAssetPath)
		}
		// process eBPF assets
		m.processAssets()
	}

	// create output file if applicable
	if len(options.OutputDirectory) > 0 {
		m.outputFile, err = ioutil.TempFile(options.OutputDirectory, "ebpfkit-monitor-*.json")
		if err != nil {
			return nil, errors.Wrapf(err, "failed to generate output file")
		}
	}
	return m, nil
}

// ShowProgram prints information about the provided program section. If no section is provided, all the programs will
// be displayed.
func (m *Monitor) ShowProgram(section string, dumpByteCode bool, helper string, mapName string) error {
	// if a program section is provided, dump program info
	if len(section) != 0 {
		programSpec, ok := m.collectionSpec.Programs[section]
		if !ok {
			return errors.Errorf("%s section not found", section)
		}

		if len(helper) > 0 {
			if m.programHelpers[programSpec.SectionName][m.helperTranslation[helper]] <= 0 {
				return errors.Errorf("section %s doesn't use eBPF helper %s", section, helper)
			}
		}

		if len(mapName) > 0 {
			if m.programMaps[programSpec.SectionName][mapName] <= 0 {
				return errors.Errorf("section %s doesn't use map %s", section, mapName)
			}
		}

		m.printProgramSpec(programSpec, dumpByteCode)
		return nil
	}

	var selectedSections []string
	var shouldFilter bool
	// select programs by helpers
	if len(helper) > 0 {
		shouldFilter = true
		for prog := range m.helpers[m.helperTranslation[helper]] {
			if len(mapName) > 0 {
				if m.programMaps[prog][mapName] > 0 {
					selectedSections = append(selectedSections, prog)
				}
			} else {
				selectedSections = append(selectedSections, prog)
			}
		}
	} else if len(mapName) > 0 {
		shouldFilter = true
		for prog := range m.mapPrograms[mapName] {
			selectedSections = append(selectedSections, prog)
		}
	}

CollectionSpec:
	for _, spec := range m.collectionSpec.Programs {
		if shouldFilter {
			selectedSection := false
			for _, section := range selectedSections {
				if section == spec.SectionName {
					selectedSection = true
				}
			}
			if !selectedSection {
				continue CollectionSpec
			}
		}
		m.printProgramSpec(spec, dumpByteCode)
	}
	return nil
}

func (m *Monitor) printProgramSpec(spec *ebpf.ProgramSpec, dumpByteCode bool) {
	fmt.Printf("%s\n", spec.Name)
	fmt.Printf("  SectionName: %s\n", spec.SectionName)
	fmt.Printf("  Type: %s\n", spec.Type)
	fmt.Printf("  InstructionsCount: %d\n", len(spec.Instructions))
	fmt.Printf("  AttachType: %d\n", spec.AttachType)
	fmt.Printf("  License: %s\n", spec.License)
	fmt.Printf("  KernelVersion: %d\n", spec.KernelVersion)
	fmt.Printf("  ByteOrder: %s\n", spec.ByteOrder)

	// Print list of eBPF helpers
	if len(m.programHelpers[spec.SectionName]) > 0 {
		fmt.Println("  Helpers:")
	}
	for helper, count := range m.programHelpers[spec.SectionName] {
		fmt.Printf("    - %s: %d\n", helper, count)
	}

	// Print list of maps
	if len(m.programMaps[spec.SectionName]) > 0 {
		fmt.Println("  Maps:")
	}
	for m, count := range m.programMaps[spec.SectionName] {
		fmt.Printf("    - %s: %d\n", m, count)
	}

	if dumpByteCode {
		fmt.Printf("  Bytecode:\n%s", spec.Instructions[1:])
	}
	fmt.Println()
}

// ShowMap prints information about the provided map section. If no section is provided, all the maps will
// be displayed.
func (m *Monitor) ShowMap(section string) error {
	// if a map section is provided, dump map info
	if len(section) != 0 {
		spec, ok := m.collectionSpec.Maps[section]
		if !ok {
			return errors.Errorf("%s section not found in %s", section, section)
		}
		m.printMapSpec(spec, section)
		return nil
	}

	// if not, dump all maps
	for sec, spec := range m.collectionSpec.Maps {
		m.printMapSpec(spec, sec)
	}
	return nil
}

func (m *Monitor) printMapSpec(spec *ebpf.MapSpec, section string) {
	fmt.Printf("%s\n", spec.Name)
	fmt.Printf("  SectionName: %s\n", section)
	fmt.Printf("  Type: %s\n", spec.Type)
	fmt.Printf("  Flags: %d\n", spec.Flags)
	fmt.Printf("  KeySize: %d\n", spec.KeySize)
	fmt.Printf("  ValueSize: %d\n", spec.ValueSize)
	fmt.Printf("  MaxEntries: %d\n", spec.MaxEntries)

	if len(m.mapPrograms[spec.Name]) > 0 {
		fmt.Println("  Programs:")
	}
	for p, count := range m.mapPrograms[spec.Name] {
		fmt.Printf("    - %s: %d\n", p, count)
	}
	fmt.Println()
}

func (m *Monitor) ShowReport() error {
	fmt.Printf("Program types report (detected %d different types):\n", len(m.programTypes))
	for t, progs := range m.programTypes {
		fmt.Printf("  - %s:\n", t)
		for p := range progs {
			fmt.Printf("    * %s\n", p)
		}
	}
	fmt.Printf("\n\n")

	fmt.Printf("eBPF helpers report (detected %d different helpers):\n", len(m.programHelpers))
	for helper, progs := range m.helpers {
		fmt.Printf("  - %s:\n", helper)
		for p, count := range progs {
			fmt.Printf("    * %s: %d\n", p, count)
		}
	}
	fmt.Printf("\n\n")

	fmt.Printf("Map types report (detected %d different types):\n", len(m.mapTypes))
	for t, maps := range m.mapTypes {
		fmt.Printf("  - %s:\n", t)
		for mp := range maps {
			fmt.Printf("    * %s\n", mp)
			for p, count := range m.mapPrograms[mp] {
				fmt.Printf("      + %s: %d\n", p, count)
			}
		}
	}
	return nil
}

func (m *Monitor) processAssets() {
	// Compute maps
	var mList []string
	for _, mp := range m.collectionSpec.Maps {
		mList = append(mList, mp.Name)
		if m.mapTypes[mp.Type] == nil {
			m.mapTypes[mp.Type] = map[string]int{}
		}
		m.mapTypes[mp.Type][mp.Name] = 1
	}

	// Compute programs
	for _, p := range m.collectionSpec.Programs {
		if m.programTypes[p.Type] == nil {
			m.programTypes[p.Type] = map[string]int{}
		}
		m.programTypes[p.Type][p.SectionName] = 1

		if len(p.Instructions) > m.maxProgLength {
			m.maxProgLength = len(p.Instructions)
		}
		for _, ins := range p.Instructions {
			if ins.OpCode.Class() == asm.JumpClass && ins.OpCode.JumpOp() == asm.Call && ins.Src != asm.PseudoCall {
				helper := asm.BuiltinFunc(ins.Constant)

				if m.helpers[helper] == nil {
					m.helpers[helper] = map[string]int{}
				}
				m.helpers[helper][p.SectionName] += 1

				if m.programHelpers[p.SectionName] == nil {
					m.programHelpers[p.SectionName] = map[asm.BuiltinFunc]int{}
				}
				m.programHelpers[p.SectionName][helper] += 1
			}
			if len(ins.Reference) > 0 && stringArrayContains(mList, ins.Reference) {
				if m.mapPrograms[ins.Reference] == nil {
					m.mapPrograms[ins.Reference] = map[string]int{}
				}
				m.mapPrograms[ins.Reference][p.SectionName] += 1

				if m.programMaps[p.SectionName] == nil {
					m.programMaps[p.SectionName] = map[string]int{}
				}
				m.programMaps[p.SectionName][ins.Reference] += 1
			}
		}
	}

	for _, progs := range m.mapPrograms {
		if len(progs) > m.maxProgsPerMap {
			m.maxProgsPerMap = len(progs)
		}
	}
}

func (m *Monitor) IsValidHelper(helper string) bool {
	if len(helper) == 0 {
		return true
	}
	return m.helperTranslation[helper] != 0
}

func (m *Monitor) Start() error {
	// fetch the current process executable path
	execPath, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return errors.Wrap(err, "couldn't fetch the current process executable path")
	}

	// prepare eBPF manager
	if err := m.setupEbpfManager(execPath); err != nil {
		return errors.Wrap(err, "failed to setup eBPF manager")
	}

	// start manager
	if err := m.manager.Start(); err != nil {
		return errors.Wrap(err, "failed to start eBPF manager")
	}
	logrus.Info("ebpfkit-monitor is now running !")
	if m.outputFile != nil {
		logrus.Infof("writting captured events to: %s", m.outputFile.Name())
	}
	return nil
}

func (m *Monitor) Stop() error {
	logrus.Info("shutting down ...")

	if err := m.manager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "failed to stop eBPF manager")
	}
	if m.outputFile != nil {
		if err := m.outputFile.Close(); err != nil {
			return errors.Wrap(err, "failed to close output file")
		}
	}
	return nil
}

func (m *Monitor) eventsHandler(cpu int, data []byte, perfMap *manager.PerfMap, m2 *manager.Manager) {
	var evt model.Event
	if _, err := evt.UnmarshalBinary(data, m.bootTime); err != nil {
		logrus.Warnf("failed to decode event: %s", err)
	}
	logrus.Debugf("%s", evt)

	if m.outputFile != nil {
		data, err := json.Marshal(evt)
		if err != nil {
			logrus.Warnf("couldn't marshall event: %v", err)
			return
		}
		_, _ = m.outputFile.Write(data)
		_, _ = m.outputFile.Write([]byte{'\n'})
	}
	return
}
