# Assertions

Fuzzamoto implements a feedback-guided assertion system inspired by
[Antithesis's sometimes
assertions](https://antithesis.com/docs/best_practices/sometimes_assertions/),
designed to both validate program correctness and guide fuzzing toward
interesting execution states.

The assertion system is only available when fuzzing with
[`fuzzamoto-libafl`](../usage/libafl.md).

## Sometimes Assertions

Sometimes assertions express properties that should be satisfied *sometimes*
during fuzzing, rather than always. They serve two critical purposes during
fuzzing campaigns:

- **Detect reachability and verify coverage** - When assertions fire, they
  confirm interesting program states are being reached. When they never fire,
  it reveals either that the program state is unreachable (potentially
  indicating a bug) or that the fuzzer isn't effective enough to reach it.
- **Guide exploration** - The fuzzer actively uses these assertions as
  objectives, directing exploration toward satisfying them through
  distance-based feedback.

Example usage:

```rust
assert_sometimes!(cond: mempool_size > 0, "Mempool is not empty");
assert_sometimes!(gt: reorg_depth, 16, "Reorgs deeper than 16 blocks may occur");
```

The macros can be used from code that runs inside the fuzzed VM, including
scenarios, oracles, and targets.

Compared to traditional aggregate source code coverage reports, sometimes
assertions provide additional insights into the explored state space. For
example, a coverage report would tell us that a chain reorganization occurred
but it would not inform us about the depth of those reorganizations.

## Always Assertions

Always assertions express invariants that must hold true at all times. They
detect violations of critical program properties:

```rust
assert_always!(lt: mempool_usage, max_mempool, "Mempool usage does not exceed the maximum");
assert_always!(lte: total_supply, 21_000_000, "Coin supply is within expected limits");
```

## Supported Assertion Types

Both `assert_sometimes!` and `assert_always!` support five variants:

- `cond: <bool>, <msg>` - Boolean condition
- `lt: <a>, <b>, <msg>` - Less than (a < b)
- `lte: <a>, <b>, <msg>` - Less than or equal (a <= b)
- `gt: <a>, <b>, <msg>` - Greater than (a > b)
- `gte: <a>, <b>, <msg>` - Greater than or equal (a >= b)

The numeric variants accept signed and unsigned integer values. Distances are
still reported as unsigned values because they represent how far an execution is
from satisfying an assertion.

## Assertions as Feedback for Guiding Fuzzing

Unlike traditional assertions that simply pass or fail, Fuzzamoto assertions
calculate a *distance* metric that guides the fuzzer. A distance of 0 means the
assertion is satisfied, while a distance greater than 0 indicates how far the
current execution is from satisfying the assertion. For example, with
`assert_sometimes!(gt: value, 100, "...")`, if `value = 150` the distance is 0
(satisfied), but if `value = 95` the distance is 6 (need to increase by 6).

This distance metric is integrated with LibAFL's feedback mechanism. The fuzzer
tracks when assertions are triggered, favors inputs that reduce the distance to
unsatisfied assertions, and discovers inputs that reach interesting states
(sometimes assertions) or violate always assertions.
