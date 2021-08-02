// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build linux

package kernel

import (
	"fmt"
	"strings"

	"github.com/cobaugh/osrelease"
	"github.com/pkg/errors"
)

// Version defines a kernel version helper
type Version struct {
	osRelease map[string]string
}

func (k *Version) String() string {
	return fmt.Sprintf("kernel %v", k.osRelease)
}

// NewKernelVersion returns a new kernel version helper
func NewKernelVersion() (*Version, error) {
	osReleasePaths := []string{
		osrelease.EtcOsRelease,
		osrelease.UsrLibOsRelease,
	}

	var release map[string]string
	var err error
	for _, osReleasePath := range osReleasePaths {
		release, err = osrelease.ReadFile(osReleasePath)
		if err == nil {
			return &Version{
				osRelease: release,
			}, nil
		}
	}

	return nil, errors.New("failed to detect operating system version")
}

// IsRH7Kernel returns whether the kernel is a rh7 kernel
func (k *Version) IsRH7Kernel() bool {
	return (k.osRelease["ID"] == "centos" || k.osRelease["ID"] == "rhel") && k.osRelease["VERSION_ID"] == "7"
}

// IsRH8Kernel returns whether the kernel is a rh8 kernel
func (k *Version) IsRH8Kernel() bool {
	return k.osRelease["PLATFORM_ID"] == "platform:el8"
}

// IsSuseKernel returns whether the kernel is a suse kernel
func (k *Version) IsSuseKernel() bool {
	return k.osRelease["ID"] == "sles" || k.osRelease["ID"] == "opensuse-leap"
}

// IsSLES12Kernel returns whether the kernel is a sles 12 kernel
func (k *Version) IsSLES12Kernel() bool {
	return k.IsSuseKernel() && strings.HasPrefix(k.osRelease["VERSION_ID"], "12")
}

// IsSLES15Kernel returns whether the kernel is a sles 15 kernel
func (k *Version) IsSLES15Kernel() bool {
	return k.IsSuseKernel() && strings.HasPrefix(k.osRelease["VERSION_ID"], "15")
}

// IsOracleUEKKernel returns whether the kernel is an oracle uek kernel
func (k *Version) IsOracleUEKKernel() bool {
	return k.osRelease["ID"] == "ol"
}
