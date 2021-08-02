package model

import "github.com/DataDog/ebpf"

type EBPFKitOptions struct {
	// static analysis option
	EBPFAssetPath string
	Section       string
	Helper        string
	Map           string
	Dump          bool

	// runtime monitoring options
	AllowedProcesses []string
}

const (
	// PathMaxLen is the maximum path allowed
	PathMaxLen = 350
)

func (o EBPFKitOptions) GetAllowedProcessesKV(executable string) []ebpf.MapKV {
	var l []ebpf.MapKV

	for _, p := range append(o.AllowedProcesses, executable) {
		buf := [PathMaxLen]byte{}
		copy(buf[:], p)
		l = append(l, ebpf.MapKV{
			Key:   buf,
			Value: uint32(1),
		})
	}

	return l
}
