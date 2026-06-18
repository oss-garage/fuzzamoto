# Fuzzing with fuzzamoto-libafl

*Make sure to understand the [system requirements](./requirements.md) before
running fuzzing campaigns.*

---

[`fuzzamoto-libafl`](https://github.com/dergoegge/fuzzamoto/tree/master/fuzzamoto-libafl)
is a LibAFL based fuzzer for Fuzzamoto operating on the fuzzamoto
[`intermediate representation`](../design/ir.md). This fuzzer exclusively
operates on the [IR
scenario](https://github.com/dergoegge/fuzzamoto/tree/master/fuzzamoto-scenarios/bin/ir.rs).

The
[Dockerfile.libafl](https://github.com/dergoegge/fuzzamoto/blob/master/Dockerfile.libafl)
at the root of the repository contains an example setup for running fuzzamoto
fuzzing campaigns with libafl.

Build the container image:

```
docker build -f Dockerfile.libafl -t fuzzamoto-libafl .
```

You can customize the Bitcoin Core source when building the image using the following build arguments:

### Build Arguments

- `OWNER`: Repository owner (default: `bitcoin`)
- `REPO`: Repository name (default: `bitcoin`)
- `PR_NUMBER`: Pull request number to build from
- `BITCOIN_COMMIT`: Specific commit hash to build

Examples:

```
docker build --build-arg PR_NUMBER=1234 -f Dockerfile.libafl -t fuzzamoto-libafl .
docker build --build-arg BITCOIN_COMMIT=abc123 -f Dockerfile.libafl -t fuzzamoto-libafl .
docker build --build-arg OWNER=abc123 --build-arg PR_NUMBER=1 -f Dockerfile.libafl -t fuzzamoto-libafl .
```

And then create a new container from it (mounting the current directory to
`/fuzzamoto`):

```
docker run --privileged -it -v $PWD:/fuzzamoto fuzzamoto-libafl bash
```

`--privileged` is required to enable the use of kvm by Nyx.

Inside the container, build the fuzzer and all scenarios:

```
cd /fuzzamoto
BITCOIND_PATH=/bitcoin/build_fuzz/bin/bitcoind cargo build --workspace --release --features fuzz
```

Then, build the crash handler and initialize the nyx share dir:

```
# Build the crash handler
clang-<version> -fPIC -DENABLE_NYX -D_GNU_SOURCE -DNO_PT_NYX \
    ./fuzzamoto-nyx-sys/src/nyx-crash-handler.c -ldl -I. -shared -o libnyx_crash_handler.so
# Initialize the nyx share dir
./target/release/fuzzamoto-cli init --sharedir /tmp/fuzzamoto_scenario-ir \
    --crash-handler /fuzzamoto/libnyx_crash_handler.so \
    --bitcoind /bitcoin/build_fuzz/bin/bitcoind \
    --scenario ./target/release/scenario-ir \
    --nyx-dir ./target/release/
```

The fuzzer uses shared memory to communicate between its instances, you'll
likely need to increase the size of `/dev/shm`:

```
# 50% is likely overkill
mount -o remount,size=50% /dev/shm
```

Then, run the fuzzer:

```
mkdir /tmp/in
./target/release/fuzzamoto-libafl \
    --input /tmp/in/ --output /tmp/out/ \
    --share /tmp/fuzzamoto_scenario-ir/ \
    --cores 0-15 # 16 cores, adjust for your system
```

Once it's running you'll see output similar to the following:

```
...
💗 time: 0h-12m-38s (x13) execs: 273166 cov: 5.443% corpus: 30988 exec/sec: 366.3 bugs: 0
📊 time: 0h-12m-38s (x13) execs: 273166 cov: 5.443% corpus: 30988 exec/sec: 366.2 bugs: 0
📊 time: 0h-12m-38s (x13) execs: 273166 cov: 5.443% corpus: 30989 exec/sec: 366.0 bugs: 0
💗 time: 0h-12m-40s (x13) execs: 273621 cov: 5.443% corpus: 30989 exec/sec: 365.7 bugs: 0
📊 time: 0h-12m-40s (x13) execs: 273621 cov: 5.443% corpus: 30989 exec/sec: 365.7 bugs: 0
...
```

📊 indicates that a new intersting input has been discovered and 💗 indicates a
heart-beat event from one of the fuzzers instances. Insect emojis such as 🪲
indicate that a new bug has been found.

## Troubleshooting

If the `cov` metric displayed in `fuzzamoto-libafl`'s output stays at 0%, then
something is likely wrong and you'll need to troubleshoot.

* Use the `--verbose` flag to get more helpful output
* Make sure the `target/` directory was created by the container you're working
  in. If it was created by e.g. another container previously, then `libafl_nyx`
  will likely not have been build in your current container and the fuzzer will
  fail to start Nyx VMs
