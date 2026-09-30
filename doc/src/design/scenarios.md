# Scenarios

Scenarios are a core concept in Fuzzamoto. They are fuzzing harnesses,
responsible for snapshot state setup, controlling fuzz input execution and
reporting results back to the fuzzer.

Each scenario needs to implement two functions:

* Scenario creation and snapshot state setup. This is where target full node
  processes are spawned and brought into the desired state for the fuzzing
  campaign.
* Testcase execution. This is where a fuzz input is executed in the context of
  the previously created state.

Each scenario is implemented to run as a standalone process inside the VM. A
convience macro `fuzzamoto_main` exists to implement the `main` function for
scenarios, which includes the necessary glue all scenarios need.

All scenarios are implemented in the
[`fuzzamoto-scenarios`](https://github.com/dergoegge/fuzzamoto/tree/master/fuzzamoto-scenarios)
crate. For example:

* [`HttpServerScenario`](https://github.com/dergoegge/fuzzamoto/tree/master/fuzzamoto-scenarios/bin/http_server.rs):
  tests Bitcoin Core's http server. It receives raw bytes from the fuzzer and
  parses them into a sequence of operations (using
  [`Arbitrary`](https://github.com/rust-fuzz/arbitrary)) to be performed on the
  server.
* [`RpcScenario`](https://github.com/dergoegge/fuzzamoto/tree/master/fuzzamoto-scenarios/bin/rpc_generic.rs):
  generic scenario for testing Bitcoin Core's RPC interface. It receives a
  sequence of RPC calls (using
  [`Arbitrary`](https://github.com/rust-fuzz/arbitrary)) and executes them
  against the target.
* [`IrScenario`](https://github.com/dergoegge/fuzzamoto/tree/master/fuzzamoto-scenarios/bin/ir.rs):
  generic scenario for testing Bitcoin full nodes through the p2p interface.
  Primarily meant to be fuzzed using `fuzzamoto-libafl` (custom fuzzer for
  [Fuzzamoto IR](./ir.md)). Built as `scenario-ir`. In addition to `getblocktxn`
  requests, it records compact block messages the node emits (`cmpctblock`,
  plus `headers`/`inv` block announcements) and drains each connection with
  recording enabled at the end of a run so that unsolicited high-bandwidth
  `cmpctblock` announcements are observed. This feeds the `GetBlockTxnGenerator`
  and `GetCompactBlockGenerator`, which simulate the BIP152 compact block
  reconstruction side.

### Probe-driven feedback loop

Some p2p flows can only be exercised in response to a message the node sends
*us*. For example, a `getblocktxn` is only meaningful after the node announces a
`cmpctblock`, and that announcement is itself triggered by a new block arriving
on a *different* connection — a single source cannot send a `cmpctblock` and a
`getblocktxn` about it.

To handle this, `IrScenario` supports a `Probe` operation. When present, the
scenario records selected messages received from the node during execution,
decodes them, and reports them back to the fuzzer (the
[probing stage](https://github.com/oss-garage/fuzzamoto/tree/master/fuzzamoto-libafl/src/stages/probe.rs)
prepends `Probe` to a testcase and runs it once). The decoded observations
(e.g. "the node sent a `getblocktxn`/`cmpctblock`/block announcement, triggered
by instruction N, on connection C") are stored as per-testcase metadata.
Generators then use that metadata to insert the appropriate response right after
the instruction that triggered it.
