## ebpfkit-monitor

`ebpfkit-monitor` is an utility that can be used to monitor suspicious eBPF activity and statically analyse eBPF bytecode.

### System requirements

- golang 1.13+
- This project was developed on an Ubuntu Focal machine (Linux Kernel 5.4) but should be compatible with 4.13+ kernels (not tested).

### Build

1) To build `ebpfkit-monitor`, run:

```shell script
# ~ make build
```

2) To install `ebpfkit-monitor` (copy to /usr/bin/ebpfkit-monitor) run:
```shell script
# ~ make install
```

### Getting started

Run `ebpfkit-monitor -h` to get help.

```shell script
# ~ ebpfkit-monitor -h
Usage:
  ebpfkit-monitor [command]

Available Commands:
  graph       graph generates a graphviz representation of the ELF file
  help        Help about any command
  map         prints information about one or multiple maps
  prog        prints information about one or multiple programs
  report      prints summarized information about the maps and programs

Flags:
  -a, --asset string   path to the eBPF asset (ELF format expected)
  -h, --help           help for ebpfkit-monitor

Use "ebpfkit-monitor [command] --help" for more information about a command.
```

### Examples

#### List all the program sections provided in the ELF file

```shell script
# ~ ebpfkit-monitor prog --asset my_elf_file.o
```

#### Dump the bytecode of a program

```shell script
# ~ ebpfkit-monitor prog --asset my_elf_file.o --section kprobe/my_program --dump
```

#### List all the maps declared in the ELF file

```shell script
# ~ ebpfkit-monitor map --asset my_elf_file.o
```
