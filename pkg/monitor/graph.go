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
	"io/ioutil"
	"os"
	"text/template"

	"github.com/DataDog/ebpf"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/blake2b"
)

var colors = []string{
	"1",
	"2",
	"3",
	"4",
	"5",
	"6",
	"7",
	"8",
	"9",
	"10",
	"11",
}

type cluster struct {
	ID    string
	Label string
	Nodes map[string]node
}

type node struct {
	ID    string
	Label string
	Size  int
	Color string
}

type edge struct {
	Link  string
	Color string
}

type graph struct {
	Title    string
	Programs []cluster
	Maps     map[string]node
	Edges    []edge
}

func (m *Monitor) GenerateGraph(title string) error {
	tmpl := `digraph {
      label     = "{{ .Title }}"
      labelloc  =  "t"
      fontsize  = 75
      fontcolor = "black"
      fontname = "arial"
      overlap = false
      splines = true

      graph [pad=2, overlap = false]
	  node [style=rounded, style="rounded", colorscheme=set39, shape=record, fontname = "arial", margin=0.3, padding=1, penwidth=3]
      edge [colorscheme=set39, penwidth=2]

	  {{ range .Maps }}
	  {{ .ID }} [label="{{ .Label }}", fontsize={{ .Size }}, shape=cylinder, color="{{ .Color }}"]{{ end }}

	  {{ range .Programs }}
	  subgraph {{ .ID }} {
	    label = "{{ .Label }}";
		{{ range .Nodes }}
	    {{ .ID }} [label="{{ .Label }}", fontsize={{ .Size }}, shape=box, color="{{ .Color }}"]{{ end }}
	  }{{ end }}
	
      {{ range .Edges }}
      {{ .Link }} [arrowhead=none, color="{{ .Color }}"]
      {{ end }}
	}
`
	data := m.prepareGraphData(title)

	f, err := ioutil.TempFile("/tmp", "ebpfkit-monitor-graph-")
	if err != nil {
		return err
	}
	defer f.Close()

	if err := os.Chmod(f.Name(), os.ModePerm); err != nil {
		return err
	}

	t := template.Must(template.New("tmpl").Parse(tmpl))
	if err := t.Execute(f, data); err != nil {
		return err
	}
	logrus.Infof("Graph generated: %s", f.Name())

	return nil
}

func (m *Monitor) prepareGraphData(title string) graph {
	data := graph{
		Title: title,
		Maps:  make(map[string]node),
	}
	var i int

	for t, progs := range m.programTypes {
		cls := cluster{
			ID:    fmt.Sprintf("cluster_%d", i),
			Label: t.String(),
			Nodes: make(map[string]node),
		}
		i++

		for p := range progs {
			var prog *ebpf.ProgramSpec
			for _, pr := range m.collectionSpec.Programs {
				if pr.SectionName == p {
					prog = pr
				}
			}
			if prog == nil {
				continue
			}
			cls.Nodes[prog.SectionName] = node{
				ID:    generateNodeID(prog.SectionName),
				Label: prog.SectionName,
				Size:  len(prog.Instructions)/m.maxProgLength*40 + 30,
				Color: colors[int(prog.Type)%len(colors)],
			}
		}
		data.Programs = append(data.Programs, cls)
	}
	for _, mp := range m.collectionSpec.Maps {
		data.Maps[mp.Name] = node{
			ID:    generateNodeID(mp.Name),
			Label: mp.Name,
			Size:  len(m.mapPrograms[mp.Name])/m.maxProgsPerMap*40 + 30,
			Color: "#8fbbff",
		}
	}

	for _, prog := range m.collectionSpec.Programs {
		for m := range m.programMaps[prog.SectionName] {
			data.Edges = append(data.Edges, edge{
				Link:  fmt.Sprintf("%s -> %s", generateNodeID(prog.SectionName), generateNodeID(m)),
				Color: colors[int(prog.Type)%len(colors)],
			})
		}
	}
	return data
}

func generateNodeID(section string) string {
	var id string
	for _, b := range blake2b.Sum256([]byte(section)) {
		id += fmt.Sprintf("%v", b)
	}
	return id
}
