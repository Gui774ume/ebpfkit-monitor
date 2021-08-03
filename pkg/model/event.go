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
	"bytes"
	"fmt"
	"time"

	"github.com/pkg/errors"
)

type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Command   BPFCmd    `json:"command"`
	Map       *Map      `json:"map,omitempty"`
	Program   *Program  `json:"program,omitempty"`
}

func (e Event) String() string {
	s := fmt.Sprintf("cmd:%s", e.Command)
	if e.Map != nil && e.Map.ID > 0 {
		s += fmt.Sprintf(" map:%s", e.Map)
	}
	if e.Program != nil && e.Program.ID > 0 {
		s += fmt.Sprintf(" prog:%s", e.Program)
	}
	return s
}

var (
	// ErrNotEnoughData is used to notify that not enough data was read from the perf buffer
	ErrNotEnoughData = errors.New("not enough data")
)

func (e *Event) UnmarshalBinary(data []byte, bootTime time.Time) (int, error) {
	var read int
	var err error

	if len(data) < 16 {
		return 0, ErrNotEnoughData
	}

	e.Timestamp = bootTime.Add(time.Duration(ByteOrder.Uint64(data[0:8])) * time.Nanosecond)
	e.Command = BPFCmd(ByteOrder.Uint32(data[8:12]))
	// padding
	cursor := 16

	e.Map = &Map{}
	if read, err = e.Map.UnmarshalBinary(data[cursor:]); err != nil {
		return 0, err
	}
	cursor += read
	if e.Map.ID == 0 {
		e.Map = nil
	}

	e.Program = &Program{}
	if read, err = e.Program.UnmarshalBinary(data[cursor:]); err != nil {
		return 0, err
	}
	cursor += read
	if e.Program.ID == 0 {
		e.Program = nil
	}
	return cursor, nil
}

type Map struct {
	ID   uint32  `json:"id"`
	Type MapType `json:"type"`
	Name string  `json:"name"`
}

func (m Map) String() string {
	return fmt.Sprintf("id:%d name:%s type:%s", m.ID, m.Name, m.Type)
}

func (m *Map) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < 24 {
		return 0, ErrNotEnoughData
	}
	m.ID = ByteOrder.Uint32(data[0:4])
	m.Type = MapType(ByteOrder.Uint32(data[4:8]))
	m.Name = bytes.NewBuffer(bytes.Trim(data[8:24], "\x00")).String()
	return 24, nil
}

type Program struct {
	ID         uint32       `json:"id"`
	Type       ProgramType  `json:"type"`
	AttachType AttachType   `json:"attach_type,omitempty"`
	Helpers    []HelperFunc `json:"helpers,omitempty"`
	Name       string       `json:"name"`
}

func (p Program) String() string {
	return fmt.Sprintf("id:%d name:%s type:%s attach_type:%d helpers:%s", p.ID, p.Name, p.Type, p.AttachType, p.Helpers)
}

func (p *Program) UnmarshalBinary(data []byte) (int, error) {
	p.ID = ByteOrder.Uint32(data[0:4])
	p.Type = ProgramType(ByteOrder.Uint32(data[4:8]))
	p.AttachType = NewAttachType(p.Type, ByteOrder.Uint32(data[8:12]))
	// padding
	helpers := []uint64{0, 0, 0}
	helpers[0] = ByteOrder.Uint64(data[16:24])
	helpers[1] = ByteOrder.Uint64(data[24:32])
	helpers[2] = ByteOrder.Uint64(data[32:40])
	p.Helpers = parseHelpers(helpers)
	p.Name = bytes.NewBuffer(bytes.Trim(data[40:56], "\x00")).String()
	return 56, nil
}

func parseHelpers(helpers []uint64) []HelperFunc {
	var rep []HelperFunc
	var add bool

	if len(helpers) < 3 {
		return rep
	}

	for i := 0; i < 192; i++ {
		add = false
		if i < 64 {
			if helpers[0]&(1<<i) == (1 << i) {
				add = true
			}
		} else if i < 128 {
			if helpers[1]&(1<<(i-64)) == (1 << (i - 64)) {
				add = true
			}
		} else if i < 192 {
			if helpers[2]&(1<<(i-128)) == (1 << (i - 128)) {
				add = true
			}
		}

		if add {
			rep = append(rep, HelperFunc(i))
		}
	}
	return rep
}
