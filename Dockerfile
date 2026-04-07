# Unified multi-stage Dockerfile for fuzzamoto
#
# Build specific targets with: docker build --target <target> .
#   Targets: aflpp, libafl, coverage, coverage-generic
#
# Build args (for Bitcoin Core source):
#   OWNER, REPO, BRANCH, PR_NUMBER, BITCOIN_COMMIT

ARG LLVM_V=19

# =============================================================================
# Stage: base
# Common dependencies: LLVM, system packages, Rust
# =============================================================================
FROM debian:bookworm AS base

ARG LLVM_V

# Add the LLVM apt repo
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates gnupg lsb-release software-properties-common wget && \
    wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh ${LLVM_V}

# Install LLVM toolchain & all build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
      ninja-build \
      libgtk-3-dev \
      pax-utils \
      python3-msgpack \
      python3-jinja2 \
      curl \
      lld-${LLVM_V} \
      llvm-${LLVM_V} \
      llvm-${LLVM_V}-dev \
      clang-${LLVM_V} \
      libclang-rt-${LLVM_V}-dev \
      cpio \
      git \
      build-essential \
      libtool \
      autotools-dev \
      automake \
      cmake \
      pkg-config \
      bsdmainutils \
      openssh-client \
      libcapstone-dev \
      python3 \
      libzstd-dev \
      libssl-dev \
      patch \
      tmux \
      vim \
      gnuplot

# Install Rust nightly and tools
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup install nightly && rustup default nightly
RUN cargo install just

# =============================================================================
# Stage: aflpp-nyx
# AFL++ built with Nyx hypervisor support
# =============================================================================
FROM base AS aflpp-nyx

ARG LLVM_V
ENV LLVM_CONFIG=llvm-config-${LLVM_V}

RUN git clone https://github.com/AFLplusplus/AFLplusplus
RUN cd AFLplusplus/nyx_mode/ && ./build_nyx_support.sh
RUN cd AFLplusplus && make PERFORMANCE=1 install -j$(nproc --ignore 1)

# =============================================================================
# Stage: aflpp-plain
# AFL++ built without Nyx (for LibAFL)
# =============================================================================
FROM base AS aflpp-plain

ARG LLVM_V
ENV LLVM_CONFIG=llvm-config-${LLVM_V}

WORKDIR /
RUN git clone https://github.com/AFLplusplus/AFLplusplus
RUN cd AFLplusplus && make PERFORMANCE=1 -j$(nproc --ignore 1)

# =============================================================================
# Stage: bitcoin-src
# Clone Bitcoin Core, download depends, apply common patches
# =============================================================================
FROM base AS bitcoin-src

ARG OWNER=bitcoin
ARG REPO=bitcoin
ARG BRANCH=master
ARG PR_NUMBER=
ARG BITCOIN_COMMIT=""

RUN git clone --depth 1 --branch "${BRANCH}" "https://github.com/${OWNER}/${REPO}.git" "${REPO}" && \
    cd "${REPO}" && \
    if [ -n "${PR_NUMBER}" ]; then \
        git fetch --depth 1 origin "pull/${PR_NUMBER}/head:pr-${PR_NUMBER}" && \
        git checkout "pr-${PR_NUMBER}"; \
    elif [ -n "${BITCOIN_COMMIT}" ]; then \
        git fetch --depth 1 origin "${BITCOIN_COMMIT}" && \
        git checkout "${BITCOIN_COMMIT}"; \
    fi

# Download depends sources (shared across all builds)
ENV SOURCES_PATH=/tmp/bitcoin-depends
RUN make -C bitcoin/depends NO_QT=1 NO_ZMQ=1 NO_USDT=1 download-linux SOURCES_PATH=$SOURCES_PATH

# Keep extracted source during depends build
RUN sed -i --regexp-extended '/.*rm -rf .*extract_dir.*/d' ./bitcoin/depends/funcs.mk

# Apply common patch
COPY ./target-patches/bitcoin-core-aggressive-rng.patch bitcoin/
RUN cd bitcoin/ && git apply bitcoin-core-aggressive-rng.patch

# =============================================================================
# Stage: bitcoin-aflpp-nyx
# Bitcoin Core built with AFL++ (Nyx) instrumentation + ASan
# =============================================================================
FROM aflpp-nyx AS bitcoin-aflpp-nyx

ARG LLVM_V

COPY --from=bitcoin-src /bitcoin /bitcoin
COPY --from=bitcoin-src /tmp/bitcoin-depends /tmp/bitcoin-depends

ENV CC=/AFLplusplus/afl-clang-fast
ENV CXX=/AFLplusplus/afl-clang-fast++
ENV SOURCES_PATH=/tmp/bitcoin-depends

RUN make -C ./bitcoin/depends DEBUG=1 NO_QT=1 NO_ZMQ=1 NO_USDT=1 \
      SOURCES_PATH=$SOURCES_PATH \
      AR=llvm-ar-${LLVM_V} NM=llvm-nm-${LLVM_V} RANLIB=llvm-ranlib-${LLVM_V} STRIP=llvm-strip-${LLVM_V} \
      -j$(nproc)

RUN cd bitcoin/ && cmake -B build_fuzz \
      --toolchain ./depends/$(./depends/config.guess)/toolchain.cmake \
      -DSANITIZERS="address" \
      -DAPPEND_CPPFLAGS="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION" \
      -DAPPEND_LDFLAGS="-fuse-ld=lld-${LLVM_V}"

RUN cmake --build bitcoin/build_fuzz -j$(nproc) --target bitcoind

ENV CC=clang-${LLVM_V}
ENV CXX=clang++-${LLVM_V}

# =============================================================================
# Stage: bitcoin-aflpp-libafl
# Bitcoin Core built with AFL++ instrumentation + denylist + ASan
# =============================================================================
FROM aflpp-plain AS bitcoin-aflpp-libafl

ARG LLVM_V

COPY --from=bitcoin-src /bitcoin /bitcoin
COPY --from=bitcoin-src /tmp/bitcoin-depends /tmp/bitcoin-depends

ENV CC=/AFLplusplus/afl-clang-fast
ENV CXX=/AFLplusplus/afl-clang-fast++
ENV LD=/AFLplusplus/afl-clang-fast
ENV SOURCES_PATH=/tmp/bitcoin-depends

COPY ./target-patches/bitcoin-core-ir-denylist.txt /denylist.txt
ENV AFL_LLVM_DENYLIST=/denylist.txt

RUN make -C ./bitcoin/depends DEBUG=1 NO_QT=1 NO_ZMQ=1 NO_USDT=1 \
      SOURCES_PATH=$SOURCES_PATH \
      AR=llvm-ar-${LLVM_V} NM=llvm-nm-${LLVM_V} RANLIB=llvm-ranlib-${LLVM_V} STRIP=llvm-strip-${LLVM_V} \
      -j$(nproc)

RUN cd bitcoin/ && cmake -B build_fuzz \
      --toolchain ./depends/$(./depends/config.guess)/toolchain.cmake \
      -DSANITIZERS="address" \
      -DAPPEND_CPPFLAGS="-DFUZZAMOTO_FUZZING -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DABORT_ON_FAILED_ASSUME" \
      -DAPPEND_LDFLAGS="-fuse-ld=lld-${LLVM_V}"

RUN cmake --build bitcoin/build_fuzz -j$(nproc) --target bitcoind

ENV CC=clang-${LLVM_V}
ENV CXX=clang++-${LLVM_V}
ENV LD=lld-${LLVM_V}

# =============================================================================
# Stage: bitcoin-cov
# Bitcoin Core built with clang + coverage instrumentation
# =============================================================================
FROM base AS bitcoin-cov

ARG LLVM_V

COPY --from=bitcoin-src /bitcoin /bitcoin
COPY --from=bitcoin-src /tmp/bitcoin-depends /tmp/bitcoin-depends

ENV CC=clang-${LLVM_V}
ENV CXX=clang++-${LLVM_V}
ENV SOURCES_PATH=/tmp/bitcoin-depends

RUN make -C ./bitcoin/depends DEBUG=1 NO_QT=1 NO_ZMQ=1 NO_USDT=1 \
      SOURCES_PATH=$SOURCES_PATH \
      AR=llvm-ar-${LLVM_V} NM=llvm-nm-${LLVM_V} RANLIB=llvm-ranlib-${LLVM_V} STRIP=llvm-strip-${LLVM_V} \
      -j$(nproc)

RUN cd bitcoin/ && cmake -B build_fuzz_cov \
      --toolchain ./depends/$(./depends/config.guess)/toolchain.cmake \
      -DAPPEND_CFLAGS="-fprofile-instr-generate -fcoverage-mapping" \
      -DAPPEND_CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping" \
      -DAPPEND_LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -fuse-ld=lld-${LLVM_V}" \
      -DAPPEND_CPPFLAGS="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"

RUN cmake --build bitcoin/build_fuzz_cov -j$(nproc) --target bitcoind

# =============================================================================
# Stage: fuzzamoto-src
# Vendored Rust workspace source (shared by aflpp and coverage targets)
# =============================================================================
FROM base AS fuzzamoto-src

WORKDIR /fuzzamoto/fuzzamoto-nyx-sys
COPY ./fuzzamoto-nyx-sys/Cargo.toml .
COPY ./fuzzamoto-nyx-sys/src/ src/
COPY ./fuzzamoto-nyx-sys/build.rs .

WORKDIR /fuzzamoto/fuzzamoto
COPY ./fuzzamoto/Cargo.toml .
COPY ./fuzzamoto/src/ src/

WORKDIR /fuzzamoto/fuzzamoto-cli
COPY ./fuzzamoto-cli/Cargo.toml .
COPY ./fuzzamoto-cli/src/ src/

WORKDIR /fuzzamoto/fuzzamoto-ir
COPY ./fuzzamoto-ir/Cargo.toml .
COPY ./fuzzamoto-ir/src/ src/
COPY ./fuzzamoto-ir/benches/ benches/

WORKDIR /fuzzamoto/fuzzamoto-libafl
COPY ./fuzzamoto-libafl/Cargo.toml .
COPY ./fuzzamoto-libafl/src/ src/

WORKDIR /fuzzamoto/fuzzamoto-scenarios
COPY ./fuzzamoto-scenarios/Cargo.toml .
COPY ./fuzzamoto-scenarios/bin/ bin/
COPY ./fuzzamoto-scenarios/rpcs.txt .

WORKDIR /fuzzamoto
COPY ./Cargo.toml .
RUN mkdir .cargo && cargo vendor > .cargo/config

# =============================================================================
# Target: aflpp
# Full AFL++/Nyx fuzzing image
# =============================================================================
FROM bitcoin-aflpp-nyx AS aflpp

ARG LLVM_V

# Install AFL_Runner and configure tmux
RUN git clone --depth 1 --branch "v0.6.0" https://github.com/0xricksanchez/AFL_Runner.git
RUN cd AFL_Runner && cargo install --path .
RUN mkdir -p /root/.config/tmux/ && \
    echo "set -g prefix C-y" > /root/.config/tmux/tmux.conf

# For CI jobs
COPY ./ci /ci

COPY --from=fuzzamoto-src /fuzzamoto /fuzzamoto

WORKDIR /fuzzamoto

ENV BITCOIND_PATH=/bitcoin/build_fuzz/bin/bitcoind
RUN cargo build --package fuzzamoto-scenarios --package fuzzamoto-cli \
      --verbose --features "fuzzamoto/fuzz,fuzzamoto-scenarios/fuzz" --release

# Build the crash handler
#   -D_GNU_SOURCE & -ldl for `#include <dlfcn.h>`
#   -DNO_PT_NYX for nyx's compile-time instrumentation mode
RUN clang-${LLVM_V} -fPIC -DENABLE_NYX -D_GNU_SOURCE -DNO_PT_NYX \
    ./fuzzamoto-nyx-sys/src/nyx-crash-handler.c -ldl -I. -shared -o libnyx_crash_handler.so

# Create Nyx share dirs for all scenarios
WORKDIR /
RUN for scenario in /fuzzamoto/target/release/scenario-*; do \
      if [ -f "$scenario" ] && [ -x "$scenario" ]; then \
      scenario_name=$(basename $scenario); \
      export SCENARIO_NYX_DIR="/tmp/fuzzamoto_${scenario_name}"; \
      /fuzzamoto/target/release/fuzzamoto-cli init \
        --sharedir $SCENARIO_NYX_DIR \
        --crash-handler ./fuzzamoto/libnyx_crash_handler.so \
        --bitcoind $BITCOIND_PATH \
        --scenario $scenario \
        --nyx-dir /AFLplusplus/nyx_mode \
        --rpc-path ./fuzzamoto/fuzzamoto-scenarios/rpcs.txt; \
      fi \
    done

# =============================================================================
# Target: libafl
# LibAFL fuzzing image (fuzzamoto source mounted at runtime)
# =============================================================================
FROM bitcoin-aflpp-libafl AS libafl

# Pin nightly for LibAFL compatibility
RUN rustup install nightly-2026-02-15 && rustup default nightly-2026-02-15

# Needed to avoid "fatal: detected dubious ownership in repository" errors from
# the Nyx build inside of target/
RUN git config --global --add safe.directory /fuzzamoto

COPY ./ci /ci

# =============================================================================
# Target: coverage
# Coverage analysis image
# =============================================================================
FROM bitcoin-cov AS coverage

ARG LLVM_V

COPY --from=fuzzamoto-src /fuzzamoto /fuzzamoto

WORKDIR /fuzzamoto

ENV BITCOIND_PATH=/bitcoin/build_fuzz_cov/bin/bitcoind
RUN cargo build -p fuzzamoto-scenarios --bins -p fuzzamoto-cli --verbose --features "reproduce" --release

ENV LLVM_V=${LLVM_V}

ENTRYPOINT ["/fuzzamoto/target/release/fuzzamoto-cli", "coverage", "--output", "/mnt/output", \
            "--corpus", "/mnt/corpus", "--bitcoind", "/bitcoin/build_fuzz_cov/bin/bitcoind", "--scenario"]

# =============================================================================
# Target: coverage-generic
# Coverage image without fixed entrypoint
# =============================================================================
FROM coverage AS coverage-generic
ENTRYPOINT []
