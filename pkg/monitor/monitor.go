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

package monitor

import (
	"fmt"
	"os"
	"strings"

	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/asm"
	"github.com/pkg/errors"
)

// Monitor is the main Monitor structure
type Monitor struct {
	collectionSpec *ebpf.CollectionSpec
	maxProgLength  int
	maxProgsPerMap int

	// eBPF helpers
	helperTranslation map[string]asm.BuiltinFunc

	// processes assets
	programTypes   map[ebpf.ProgramType]map[string]int
	programMaps    map[string]map[string]int
	programHelpers map[string]map[asm.BuiltinFunc]int
	helpers        map[asm.BuiltinFunc]map[string]int
	mapTypes       map[ebpf.MapType]map[string]int
	mapPrograms    map[string]map[string]int
}

func (e *Monitor) parseAsset(asset string) error {
	if _, err := os.Stat(asset); err != nil {
		return err
	}

	f, err := os.Open(asset)
	if err != nil {
		return err
	}

	e.collectionSpec, err = ebpf.LoadCollectionSpecFromReader(f)
	if err != nil {
		return err
	}
	return nil
}

// NewMonitor returns a new Monitor instance
func NewMonitor(asset string) (*Monitor, error) {
	e := &Monitor{
		helperTranslation: make(map[string]asm.BuiltinFunc),
		programTypes:      make(map[ebpf.ProgramType]map[string]int),
		programMaps:       make(map[string]map[string]int),
		programHelpers:    make(map[string]map[asm.BuiltinFunc]int),
		helpers:           make(map[asm.BuiltinFunc]map[string]int),
		mapTypes:          make(map[ebpf.MapType]map[string]int),
		mapPrograms:       make(map[string]map[string]int),
	}

	// build eBPF helper translation
	var i int
	var helper asm.BuiltinFunc
	for {
		helper = asm.BuiltinFunc(i)
		if !strings.HasPrefix(helper.String(), "BuiltinFunc") {
			e.helperTranslation[helper.String()] = helper
			i++
		} else {
			break
		}
	}

	// parse asset
	if err := e.parseAsset(asset); err != nil {
		return nil, errors.Wrapf(err, "couldn't parse asset %s", asset)
	}

	// process eBPF assets
	e.processAssets()
	return e, nil
}

// ShowProgram prints information about the provided program section. If no section is provided, all the programs will
// be displayed.
func (e *Monitor) ShowProgram(section string, dumpByteCode bool, helper string, m string) error {
	// if a program section is provided, dump program info
	if len(section) != 0 {
		spec, ok := e.collectionSpec.Programs[section]
		if !ok {
			return errors.Errorf("%s section not found", section)
		}

		if len(helper) > 0 {
			if e.programHelpers[spec.SectionName][e.helperTranslation[helper]] <= 0 {
				return errors.Errorf("section %s doesn't use eBPF helper %s", section, helper)
			}
		}

		if len(m) > 0 {
			if e.programMaps[spec.SectionName][m] <= 0 {
				return errors.Errorf("section %s doesn't use map %s", section, m)
			}
		}

		e.printProgramSpec(spec, dumpByteCode)
		return nil
	}

	var selectedSections []string
	var shouldFilter bool
	// select programs by helpers
	if len(helper) > 0 {
		shouldFilter = true
		for prog := range e.helpers[e.helperTranslation[helper]] {
			if len(m) > 0 {
				if e.programMaps[prog][m] > 0 {
					selectedSections = append(selectedSections, prog)
				}
			} else {
				selectedSections = append(selectedSections, prog)
			}
		}
	} else if len(m) > 0 {
		shouldFilter = true
		for prog := range e.mapPrograms[m] {
			selectedSections = append(selectedSections, prog)
		}
	}

CollectionSpec:
	for _, spec := range e.collectionSpec.Programs {
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
		e.printProgramSpec(spec, dumpByteCode)
	}
	return nil
}

func (e *Monitor) printProgramSpec(spec *ebpf.ProgramSpec, dumpByteCode bool) {
	fmt.Printf("%s\n", spec.Name)
	fmt.Printf("  SectionName: %s\n", spec.SectionName)
	fmt.Printf("  Type: %s\n", spec.Type)
	fmt.Printf("  InstructionsCount: %d\n", len(spec.Instructions))
	fmt.Printf("  AttachType: %d\n", spec.AttachType)
	fmt.Printf("  License: %s\n", spec.License)
	fmt.Printf("  KernelVersion: %d\n", spec.KernelVersion)
	fmt.Printf("  ByteOrder: %s\n", spec.ByteOrder)

	// Print list of eBPF helpers
	if len(e.programHelpers[spec.SectionName]) > 0 {
		fmt.Println("  Helpers:")
	}
	for helper, count := range e.programHelpers[spec.SectionName] {
		fmt.Printf("    - %s: %d\n", helper, count)
	}

	// Print list of maps
	if len(e.programMaps[spec.SectionName]) > 0 {
		fmt.Println("  Maps:")
	}
	for m, count := range e.programMaps[spec.SectionName] {
		fmt.Printf("    - %s: %d\n", m, count)
	}

	if dumpByteCode {
		fmt.Printf("  Bytecode:\n%s", spec.Instructions[1:])
	}
	fmt.Println()
}

// ShowMap prints information about the provided map section. If no section is provided, all the maps will
// be displayed.
func (e *Monitor) ShowMap(section string) error {
	// if a map section is provided, dump map info
	if len(section) != 0 {
		spec, ok := e.collectionSpec.Maps[section]
		if !ok {
			return errors.Errorf("%s section not found in %s", section, section)
		}
		e.printMapSpec(spec, section)
		return nil
	}

	// if not, dump all maps
	for sec, spec := range e.collectionSpec.Maps {
		e.printMapSpec(spec, sec)
	}
	return nil
}

func (e *Monitor) printMapSpec(spec *ebpf.MapSpec, section string) {
	fmt.Printf("%s\n", spec.Name)
	fmt.Printf("  SectionName: %s\n", section)
	fmt.Printf("  Type: %s\n", spec.Type)
	fmt.Printf("  Flags: %d\n", spec.Flags)
	fmt.Printf("  KeySize: %d\n", spec.KeySize)
	fmt.Printf("  ValueSize: %d\n", spec.ValueSize)
	fmt.Printf("  MaxEntries: %d\n", spec.MaxEntries)

	if len(e.mapPrograms[spec.Name]) > 0 {
		fmt.Println("  Programs:")
	}
	for p, count := range e.mapPrograms[spec.Name] {
		fmt.Printf("    - %s: %d\n", p, count)
	}
	fmt.Println()
}

func (e *Monitor) ShowReport() error {
	fmt.Printf("Program types report (detected %d different types):\n", len(e.programTypes))
	for t, progs := range e.programTypes {
		fmt.Printf("  - %s:\n", t)
		for p := range progs {
			fmt.Printf("    * %s\n", p)
		}
	}
	fmt.Printf("\n\n")

	fmt.Printf("eBPF helpers report (detected %d different helpers):\n", len(e.programHelpers))
	for helper, progs := range e.helpers {
		fmt.Printf("  - %s:\n", helper)
		for p, count := range progs {
			fmt.Printf("    * %s: %d\n", p, count)
		}
	}
	fmt.Printf("\n\n")

	fmt.Printf("Map types report (detected %d different types):\n", len(e.mapTypes))
	for t, maps := range e.mapTypes {
		fmt.Printf("  - %s:\n", t)
		for m := range maps {
			fmt.Printf("    * %s\n", m)
			for p, count := range e.mapPrograms[m] {
				fmt.Printf("      + %s: %d\n", p, count)
			}
		}
	}
	return nil
}

func (e *Monitor) processAssets() {
	// Compute maps
	var mList []string
	for _, m := range e.collectionSpec.Maps {
		mList = append(mList, m.Name)
		if e.mapTypes[m.Type] == nil {
			e.mapTypes[m.Type] = map[string]int{}
		}
		e.mapTypes[m.Type][m.Name] = 1
	}

	// Compute programs
	for _, p := range e.collectionSpec.Programs {
		if e.programTypes[p.Type] == nil {
			e.programTypes[p.Type] = map[string]int{}
		}
		e.programTypes[p.Type][p.SectionName] = 1

		if len(p.Instructions) > e.maxProgLength {
			e.maxProgLength = len(p.Instructions)
		}
		for _, ins := range p.Instructions {
			if ins.OpCode.Class() == asm.JumpClass && ins.OpCode.JumpOp() == asm.Call && ins.Src != asm.PseudoCall {
				helper := asm.BuiltinFunc(ins.Constant)

				if e.helpers[helper] == nil {
					e.helpers[helper] = map[string]int{}
				}
				e.helpers[helper][p.SectionName] += 1

				if e.programHelpers[p.SectionName] == nil {
					e.programHelpers[p.SectionName] = map[asm.BuiltinFunc]int{}
				}
				e.programHelpers[p.SectionName][helper] += 1
			}
			if len(ins.Reference) > 0 && stringArrayContains(mList, ins.Reference) {
				if e.mapPrograms[ins.Reference] == nil {
					e.mapPrograms[ins.Reference] = map[string]int{}
				}
				e.mapPrograms[ins.Reference][p.SectionName] += 1

				if e.programMaps[p.SectionName] == nil {
					e.programMaps[p.SectionName] = map[string]int{}
				}
				e.programMaps[p.SectionName][ins.Reference] += 1
			}
		}
	}

	for _, progs := range e.mapPrograms {
		if len(progs) > e.maxProgsPerMap {
			e.maxProgsPerMap = len(progs)
		}
	}
}

func (e *Monitor) IsValidHelper(helper string) bool {
	if len(helper) == 0 {
		return true
	}
	return e.helperTranslation[helper] != 0
}

func stringArrayContains(array []string, elem string) bool {
	for _, a := range array {
		if elem == a {
			return true
		}
	}
	return false
}
