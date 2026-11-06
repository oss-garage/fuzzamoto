# Reproducing Testcases

Crashing or other interesting inputs can be reproduced without the snapshotting
VM, by building the scenario binary without the nyx feature and supplying it
the input either through `stdin` or the `FUZZAMOTO_INPUT` environment variable.

Build all scenarios for reproduction purposes:

```
cargo build --release --package fuzzamoto-scenarios --features reproduce
```

`--features reproduce` is used to enable features useful for reproduction, e.g.
inherit stdout from the target application, such that any logs, stack traces,
etc. are printed to the terminal.


## `http-server` example (Out-of-VM execution)

You can run the scenario directly to debug out-of-VM execution with a
`bitcoind` binary:

First, compile the scenario with the `reproduce` features:
```
cargo build --release -p fuzzamoto-scenarios --features "fuzzamoto/reproduce","force_send_and_ping"
```

Then, run the scenario with the input supplied through `stdin`:

```
cat ./testcase.dat | RUST_LOG=info ./target/release/scenario-http-server ./bitcoind
# Use "echo '<input base64>' | base64 --decode | ..." if you have the input as a base64 string
```

Or alternatively using `FUZZAMOTO_INPUT`:

```
FUZZAMOTO_INPUT=$PWD/testcase.dat RUST_LOG=info ./target/release/scenario-http-server ./bitcoind
```

## `ir` example (In-VM execution)
You can also use the `-r` option to debug in-VM execution of the scenario.

First, build all the packages with both the `fuzz` and `nyx_log` features:
```
cd /fuzzamoto
BITCOIND_PATH=/bitcoin/build_fuzz/bin/bitcoind cargo build --workspace --release --features fuzz,nyx_log,inherit_stdout
```

The `nyx_log` feature is necessary because it allows us to retrieve the
`bitcoind` log later. You can also add the `inherit_stdout` feature if you want
more verbose logs from `bitcoind`.

Then, build the crash handler and initialize the nyx share dir as usual:

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

Now, run the fuzzer with the `-r` option:
```
RUST_LOG=info ./target/release/fuzzamoto-libafl \
    --input /tmp/in --output /tmp/out/ \
    --share /tmp/fuzzamoto_scenario-ir/ \
    -r <path to the testcase> \
    --cores 0 --verbose
```
This executes the given testcase once in reproduce mode.

After this, the `bitcoind` log is available at `/tmp/out/workdir/dump/primary.log`.

## Troubleshooting

* Make sure to not use the `nyx` feature or else you'll see:
  ```
  ...
  Segmentation fault (core dumped)
  ```

* If you see the following output, try killing any left over `bitcoind`
  instances or retry reproduction until it works:
  ```
  ...
  Error: Unable to bind to 127.0.0.1:34528 on this computer. Bitcoin Core is probably already running.
  Error: Failed to listen on any port. Use -listen=0 if you want this.
  
  thread 'main' panicked at /fuzzamoto/vendor/corepc-node/src/lib.rs:389:59:
  failed to create client: Io(Os { code: 2, kind: NotFound, message: "No such file or directory" })
  ...
  ```

* If an input does not reproduce, check that you are compiling with all
  necessary features relevant for your case, such as `compile_in_vm`,
  `force_send_and_ping` and `reduced_pow` (these should all be enabled if
  compiling with the `reproduce` feature). Also check that `bitcoind` was build
  with all required patches applied (see
  [target-patches/](https://github.com/dergoegge/fuzzamoto/tree/master/target-patches)
  and [Patches](./target-patches.md)).

* If the input still does not reproduce (e.g. `bitcoind` does not crash), the
  crash might be non-deterministic. Have fun debugging!
