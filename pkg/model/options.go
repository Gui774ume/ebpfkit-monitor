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

package model

import (
	"fmt"

	"github.com/DataDog/ebpf"
	"github.com/sirupsen/logrus"
)

type EBPFKitOptions struct {
	LogLevel logrus.Level

	// static analysis option
	EBPFAssetPath string
	Section       string
	Helper        string
	Map           string
	Dump          bool

	// runtime monitoring options
	AllowedProcesses []string
	OutputDirectory  string
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

// LogLevelSanitizer is a log level sanitizer that ensures that the provided log level exists
type LogLevelSanitizer struct {
	logLevel *logrus.Level
}

// NewLogLevelSanitizer creates a new instance of LogLevelSanitizer. The sanitized level will be written in the provided
// logrus level
func NewLogLevelSanitizer(sanitizedLevel *logrus.Level) *LogLevelSanitizer {
	*sanitizedLevel = logrus.InfoLevel
	return &LogLevelSanitizer{
		logLevel: sanitizedLevel,
	}
}

func (lls *LogLevelSanitizer) String() string {
	return fmt.Sprintf("%v", *lls.logLevel)
}

func (lls *LogLevelSanitizer) Set(val string) error {
	sanitized, err := logrus.ParseLevel(val)
	if err != nil {
		return err
	}
	*lls.logLevel = sanitized
	return nil
}

func (lls *LogLevelSanitizer) Type() string {
	return "string"
}
