package monitor

import (
	"bytes"
	"math"

	"github.com/Gui774ume/ebpfkit-monitor/pkg/assets"

	"github.com/pkg/errors"

	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/manager"
	"golang.org/x/sys/unix"
)

const (
	// EBPFKitMonitorID is used to identify ebpfkit-monitor's probes
	EBPFKitMonitorID = "ebpfkitMonitor"
)

func (m *Monitor) getAllProbes() []*manager.Probe {
	attrProbes := []*manager.Probe{
		{Section: "tracepoint/sched/sched_process_exec", UID: EBPFKitMonitorID},
		{Section: "tracepoint/sched/sched_process_fork", UID: EBPFKitMonitorID},
		{Section: "tracepoint/sched/sched_process_exit", UID: EBPFKitMonitorID},
	}

	// Make sure to append the bpf probe at the end, otherwise there is a race condition that might prevent the monitor
	// from loading further eBPF programs
	attrProbes = append(attrProbes, ExpandSyscallProbes(&manager.Probe{
		UID:             EBPFKitMonitorID,
		SyscallFuncName: "bpf",
	}, Entry)...)

	return attrProbes
}

func (m *Monitor) getManagerOptions() manager.Options {
	options := manager.Options{
		// DefaultKProbeMaxActive is the maximum number of active kretprobe at a given time
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				// LogSize is the size of the log buffer given to the verifier. Give it a big enough (2 * 1024 * 1024)
				// value so that all our programs fit. If the verifier ever outputs a `no space left on device` error,
				// we'll need to increase this value.
				LogSize: 2097152,
			},
		},

		// Extend RLIMIT_MEMLOCK (8) size
		// On some systems, the default for RLIMIT_MEMLOCK may be as low as 64 bytes.
		// This will result in an EPERM (Operation not permitted) error, when trying to create an eBPF map
		// using bpf(2) with BPF_MAP_CREATE.
		//
		// We are setting the limit to infinity until we have a better handle on the true requirements.
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}

	if len(m.options.AllowedProcesses) > 0 {
		options.ConstantEditors = append(options.ConstantEditors, manager.ConstantEditor{
			Name:  "protect_bpf",
			Value: uint64(1),
		})
	}

	return options
}

func (m *Monitor) setupEbpfManager(executable string) error {
	// set new manager
	m.manager = &manager.Manager{
		Probes: m.getAllProbes(),
		Maps: []*manager.Map{
			{Name: "allowed_binaries", Contents: m.options.GetAllowedProcessesKV(executable)},
		},
	}

	// retrieve assets
	buf, err := assets.Asset("/probe.o")
	if err != nil {
		return errors.Wrap(err, "failed to retrieve eBPF bytecode")
	}

	// init manager
	if err = m.manager.InitWithOptions(bytes.NewReader(buf), m.getManagerOptions()); err != nil {
		return errors.Wrap(err, "failed to init eBPF manager")
	}
	return nil
}
