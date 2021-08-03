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
