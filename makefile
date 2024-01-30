up:
	RUST_LOG=info cargo xtask run -- --iface enp4s0

build:
	cargo xtask build-ebpf

rebuild:
	make build & make up

list:
	sudo bpftool prog list