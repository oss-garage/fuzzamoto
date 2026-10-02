# Fuzzing Erlay

The `erlay` feature configures the IR scenario for the full Erlay implementation (Bitcoin Core PR 
#35591). It adds an `outbound-full-recon` connection so Bitcoin Core is exercised as the reconciliation 
initiator, while the existing inbound Erlay connections exercise it as the responder.

The feature also enables protocol-aware generation for `sendtxrcncl`, `reqtxrcncl`, `sketch`,
`reqsketchext`, and `reconcildiff`. Generated payloads include valid encodings, malformed
CompactSize values, protocol boundary values, and short request/extension/finalization sequences.

`ErlayReconciliationGenerator` runs complete reconciliation rounds over transactions the program
has relayed to the target. The harness records the salt the target announces in `sendtxrcncl` on
each pre-existing reconciliation link (`recon_salts` in `ir.context`), so the compiler can derive
the same short ids as the target and build sketches it decodes and `reconcildiff` requests that
name its transactions. With `bitcoin-core-aggressive-rng.patch` the target's salt is identical
on every link and run.

## Build

Build the PR with ASan instrumentation using the existing LibAFL image:

```sh
docker build --build-arg PR_NUMBER=35591 \
  -f Dockerfile.libafl -t fuzzamoto-erlay .
docker run --privileged -it -v "$PWD:/fuzzamoto" fuzzamoto-erlay bash
```

Inside the container, build Fuzzamoto with Erlay enabled:

```sh
cd /fuzzamoto
BITCOIND_PATH=/bitcoin/build_fuzz/bin/bitcoind \
  cargo build --workspace --release --features fuzz,erlay
```

Build the crash handler and initialize the Nyx share directory as described in the regular
LibAFL documentation:

```sh
clang-19 -fPIC -DENABLE_NYX -D_GNU_SOURCE -DNO_PT_NYX \
  ./fuzzamoto-nyx-sys/src/nyx-crash-handler.c -ldl -I. -shared \
  -o libnyx_crash_handler.so

./target/release/fuzzamoto-cli init \
  --sharedir /tmp/fuzzamoto-erlay \
  --crash-handler /fuzzamoto/libnyx_crash_handler.so \
  --bitcoind /bitcoin/build_fuzz/bin/bitcoind \
  --scenario ./target/release/scenario-ir \
  --nyx-dir ./target/release/
```

The VM dumps the matching `ir.context` to `<output>/workdir/dump/ir.context` on its first boot,
so start one short fuzzing run with an empty input directory to obtain it. Then generate an initial
corpus containing Erlay messages, transactions, and time advancement so reconciliation sets and
scheduled outbound rounds are reachable from the start of the campaign. `TxoGenerator` is needed
for the transaction generators to find outputs to spend:

```sh
mkdir -p /tmp/erlay-in /tmp/erlay-out
./target/release/fuzzamoto-cli ir generate \
  --output /tmp/erlay-in \
  --iterations 12 \
  --programs 512 \
  --context ./ir.context \
  --generators TxoGenerator,SingleTxGenerator,OneParentOneChildGenerator,AdvanceTimeGenerator,ErlayMessageGenerator,ErlayReconciliationGenerator
```

Run the normal crash and state-machine campaign:

```sh
./target/release/fuzzamoto-libafl \
  --input /tmp/erlay-in \
  --output /tmp/erlay-out \
  --share /tmp/fuzzamoto-erlay \
  --cores 0-15
```

Run a separate build with `v2transport` added to the scenario features to cover the same protocol
over BIP324. Use a separate share and output directory because the VM snapshot differs.

## Short id collision campaign

Short id collisions and the reconciliation set limit are unreachable with Bitcoin Core's real
parameters: ids are 32 bits and sets hold up to 3000 transactions.
`target-patches/bitcoin-core-erlay-collisions.patch` reduces short ids to `1..=255` and the set
limit to 8. Build a separate image with it, and build Fuzzamoto with `erlay_collisions` so the
harness derives short ids the same way:

```sh
docker build --build-arg PR_NUMBER=35591 \
  --build-arg EXTRA_TARGET_PATCH=bitcoin-core-erlay-collisions.patch \
  -f Dockerfile.libafl -t fuzzamoto-erlay-collisions .

BITCOIND_PATH=/bitcoin/build_fuzz/bin/bitcoind \
  cargo build --workspace --release --features fuzz,erlay_collisions
```

Relay many transactions so peers' sets fill up, e.g. by enabling `LongChainGenerator` next to
`ErlayReconciliationGenerator`. The patch changes protocol behavior, so confirm any finding
against an unpatched build before reporting it.

## Resource-exhaustion campaign

Maximum-capacity sketch decoding is intentionally excluded from the normal mutation schedule. It
can take multiple seconds per message and would otherwise dominate execution time and corpus
selection.

Generate a separate corpus for capacity boundaries:

```sh
mkdir -p /tmp/erlay-dos-in /tmp/erlay-dos-out
./target/release/fuzzamoto-cli ir generate \
  --output /tmp/erlay-dos-in \
  --iterations 10 \
  --programs 1024 \
  --context ./ir.context \
  --generators ErlayExpensiveSketchGenerator,SingleTxGenerator,AdvanceTimeGenerator
```

Run it on a small number of cores with hang reporting enabled:

```sh
./target/release/fuzzamoto-libafl \
  --input /tmp/erlay-dos-in \
  --output /tmp/erlay-dos-out \
  --share /tmp/fuzzamoto-erlay \
  --cores 0-1 \
  --timeout 1000 \
  --hang-multiple 5 \
  --mutators InputMutator,OperationMutator,ErlayExpensiveSketchGenerator,SingleTxGenerator,AdvanceTimeGenerator
```

Treat expected maximum-sketch timeouts separately from deadlocks. Re-run minimized hangs with a
larger timeout and inspect whether the node eventually answers pings from other peers.
