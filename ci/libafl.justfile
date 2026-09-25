[working-directory: '/fuzzamoto']
compile:
	BITCOIND_PATH=/bitcoin/build_fuzz/bin/bitcoind cargo build --workspace --release --features fuzz

# Enables the `bench` feature on top of `fuzz` so the fuzzer emits time-series
# stats (bench-cpu_000.csv) used by the benchmarking pipeline.
# Compile the fuzzer with benchmarking stats enabled.
[working-directory: '/fuzzamoto']
compile_bench:
	BITCOIND_PATH=/bitcoin/build_fuzz/bin/bitcoind cargo build --workspace --release --features fuzz,bench

# Independent of which fuzzer feature set was compiled, so it is reused by both
# `compile_nyx` (debug/test runs) and `bench` (benchmark runs).
# Build the Nyx crash handler and initialise the Nyx share dir.
[working-directory: '/fuzzamoto']
nyx_init:
	clang-19 -fPIC -DENABLE_NYX -D_GNU_SOURCE -DNO_PT_NYX ./fuzzamoto-nyx-sys/src/nyx-crash-handler.c -ldl -I. -shared -o libnyx_crash_handler.so
	./target/release/fuzzamoto-cli init --sharedir /tmp/fuzzamoto_scenario-ir --crash-handler /fuzzamoto/libnyx_crash_handler.so --bitcoind /bitcoin/build_fuzz/bin/bitcoind --scenario ./target/release/scenario-ir --nyx-dir ./target/release/ --sanitizer ${SANITIZER:-asan}

[working-directory: '/fuzzamoto']
compile_nyx: compile nyx_init

[working-directory: '/fuzzamoto']
corpus:
	mkdir /tmp/in

[working-directory: '/fuzzamoto']
run:	compile compile_nyx corpus
	./target/release/fuzzamoto-libafl --input /tmp/in/ --output /tmp/out/ --share /tmp/fuzzamoto_scenario-ir/ --cores 0 --verbose

# Used by the benchmarking CI pipeline (.github/workflows/benchmark.yml). Assumes the
# fuzzer is already compiled and the Nyx share dir initialised (the benchmark build stage
# bakes both into the image via Dockerfile.libafl.bench), so this only runs the campaign.
# The run is bounded by `timeout`, which exits 124 at the limit - that is the expected,
# successful outcome, hence `|| true`. Uses all cores on the instance; each core emits its
# own snapshot file (/tmp/out/bench/bench-cpu_NNN.csv), aggregated per campaign by
# ci/benchmark-evaluation.py. Crashes live in /tmp/out/cpu_NNN/crashes. Env vars:
#   BENCH_DURATION  seconds to fuzz for (default 3600 = 1h)
#   BENCH_SNAPSHOT  seconds between stats snapshots (default 30)
# Run an all-cores, time-bounded benchmarking campaign (prebuilt fuzzer required).
[working-directory: '/fuzzamoto']
bench_run: corpus
	#!/bin/bash
	# --verbose so the fuzzing clients' stdout/stderr is inherited rather than sent to
	# /dev/null (see fuzzer.rs); without it, a client that dies during startup (e.g. Nyx
	# VM bring-up failing) leaves no trace and the broker just exits.
	timeout "${BENCH_DURATION:-3600}s" \
		./target/release/fuzzamoto-libafl --input /tmp/in/ --output /tmp/out/ --share /tmp/fuzzamoto_scenario-ir/ --cores all --verbose --bench-snapshot-secs "${BENCH_SNAPSHOT:-30}" || true

# All-in-one (compile + Nyx init + run); convenient for running a benchmark locally.
[working-directory: '/fuzzamoto']
bench: compile_bench nyx_init bench_run

[working-directory: '/fuzzamoto']
clean:
	rm -rf /tmp/in && rm -rf /tmp/out && cargo clean

[working-directory: '/fuzzamoto']
test: compile compile_nyx corpus
	#!/bin/bash
	# Nested-virt runners boot the Nyx VM slowly, so poll for progress rather than using a
	# fixed budget: pass as soon as the corpus reaches 15, fail after 180s.
	./target/release/fuzzamoto-libafl --input /tmp/in/ --output /tmp/out/ --share /tmp/fuzzamoto_scenario-ir/ --cores 0 --verbose > stdout.log &
	pid=$!
	corpus=0
	for _ in $(seq 180); do
		corpus=$(grep -oaE 'corpus: [0-9]+' stdout.log | awk '{ if ($2 > m) m = $2 } END { print m + 0 }')
		if [ "$corpus" -ge 15 ]; then
			echo "Fuzzer is working (corpus: $corpus)"
			kill "$pid"
			exit 0
		fi
		kill -0 "$pid" 2>/dev/null || break
		sleep 1
	done
	echo "Fuzzer does not generate enough testcases (corpus: $corpus)"
	tail -n 50 stdout.log
	kill "$pid" 2>/dev/null
	exit 1
	