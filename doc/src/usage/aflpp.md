# Fuzzing with AFL++

*Make sure to understand the [system requirements](./requirements.md) before
running fuzzing campaigns.*

---

All fuzzamoto [scenarios](../design/scenarios.md) can be fuzzed with
[AFL++](https://github.com/AFLplusplus/AFLplusplus)'s nyx mode, except for the
[IR](../design/ir.md) scenario (`scenario-ir`).

The [Dockerfile](https://github.com/dergoegge/fuzzamoto/blob/master/Dockerfile)
at the root of the repository contains an example setup for running fuzzamoto
fuzzing campaigns with AFL++. The `aflpp` build target produces the image.

Build the container image:
```
docker build --target aflpp -t fuzzamoto .
```

You can customize the Bitcoin Core source when building the image using the following build arguments:

### Build Arguments

- `OWNER`: Repository owner (default: `bitcoin`)
- `REPO`: Repository name (default: `bitcoin`)
- `PR_NUMBER`: Pull request number to build from
- `BITCOIN_COMMIT`: Specific commit hash to build

Examples:

```
docker build --target aflpp --build-arg PR_NUMBER=1234 -t fuzzamoto .
docker build --target aflpp --build-arg BITCOIN_COMMIT=abc123 -t fuzzamoto .
docker build --target aflpp --build-arg OWNER=abc123 --build-arg PR_NUMBER=1 -t fuzzamoto .
```

And then create a new container from it:

```
docker run --privileged -it fuzzamoto bash
```

`--privileged` is required to enable the use of kvm by Nyx.

### Example: `http-server`

*All commands in this example are supposed to be run inside the docker
container.*

AFL++ can't start from an empty corpus, so unless you already have a seed
corpus available, you'll need to create or find at least one seed input
(ideally this is a useful seed not just "AAA"):

```
mkdir /tmp/in && echo "AAA" > /tmp/in/A
```

Once the seed corpus is ready, you'll be able to start the fuzzing campaign:

```
/AFLplusplus/afl-fuzz -X -i /tmp/in -o /tmp/out -- /tmp/fuzzamoto_scenario-http-server
```

## Multi-core campaigns

Running a multi-core campaign is best practice to make use of all available
cores. This can be done with
[`AFL_Runner`](https://github.com/0xricksanchez/AFL_Runner) (installed in the
`aflpp` target of the [Dockerfile](https://github.com/dergoegge/fuzzamoto/blob/master/Dockerfile)).

### Example: `http-server`

```
aflr run --nyx-mode --target /tmp/fuzzamoto_scenario-http-server/ \
    --input-dir /tmp/http_in/ --output-dir /tmp/http_out/ \
    --runners 16
```
