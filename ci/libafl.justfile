[working-directory: '/fuzzamoto']
compile:
	BITCOIND_PATH=/bitcoin/build_fuzz/bin/bitcoind cargo build --workspace --release --features fuzz

[working-directory: '/fuzzamoto']
compile_nyx: compile
	clang-21 -fPIC -DENABLE_NYX -D_GNU_SOURCE -DNO_PT_NYX ./fuzzamoto-nyx-sys/src/nyx-crash-handler.c -ldl -I. -shared -o libnyx_crash_handler.so
	./target/release/fuzzamoto-cli init --sharedir /tmp/fuzzamoto_scenario-ir --crash-handler /fuzzamoto/libnyx_crash_handler.so --bitcoind /bitcoin/build_fuzz/bin/bitcoind --scenario ./target/release/scenario-ir --nyx-dir ./target/release/

[working-directory: '/fuzzamoto']
corpus:
	mkdir /tmp/in

[working-directory: '/fuzzamoto']
run:	compile compile_nyx corpus
	./target/release/fuzzamoto-libafl --input /tmp/in/ --output /tmp/out/ --share /tmp/fuzzamoto_scenario-ir/ --cores 0 --verbose

[working-directory: '/fuzzamoto']
clean:
	rm -rf /tmp/in && rm -rf /tmp/out && cargo clean

[working-directory: '/fuzzamoto']
test: compile compile_nyx corpus
	#!/bin/bash
	timeout 16s sh -c './target/release/fuzzamoto-libafl --input /tmp/in/ --output /tmp/out/ --share /tmp/fuzzamoto_scenario-ir/ --cores 0 --verbose > stdout.log'
	if grep -qa "corpus: 15" stdout.log; then
		echo "Fuzzer is working"
	else 
		echo "Fuzzer does not generate enough testcases"
		exit 1
	fi
	