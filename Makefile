all: build install

build:
	mkdir -p bin/
	go build -o bin/ ./cmd/ebpfkit-monitor

install:
	sudo cp ./bin/ebpfkit-monitor /usr/bin/
