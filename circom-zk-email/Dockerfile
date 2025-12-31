FROM rust:1.82-bullseye AS circom-builder

WORKDIR /build

# Build circom 2.x from source (Rust compiler).
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/* && \
    git clone --branch v2.2.3 --depth 1 https://github.com/iden3/circom.git . && \
    cargo build --release

FROM node:22-bullseye

WORKDIR /app

# Install build dependencies for rapidsnark (GMP, cmake, nasm, etc.)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      git build-essential cmake g++ python3 libgmp-dev nasm && \
    rm -rf /var/lib/apt/lists/*

# Copy circom 2.2.3 binary from the builder stage.
COPY --from=circom-builder /build/target/release/circom /usr/local/bin/circom

# Build rapidsnark from source inside the image
WORKDIR /opt
RUN git config --global http.postBuffer 524288000 && \
    git clone --recurse-submodules --depth 1 https://github.com/iden3/rapidsnark.git && \
    cd rapidsnark && \
    npm install && \
    mkdir -p build && cd build && \
    cmake -DUSE_ASM=OFF .. && \
    make -j"$(nproc)" prover

ENV RAPIDSNARK=/opt/rapidsnark/build/src/prover
ENV USE_RAPIDSNARK=1

# App dependencies and code
WORKDIR /app
COPY circom-zk-email ./circom-zk-email
COPY zk-email-verifier-contract ./zk-email-verifier-contract

WORKDIR /app/circom-zk-email

# Install Node deps for circom-zk-email (ts-node, snarkjs, express, etc.).
RUN npm install

EXPOSE 5588
ENV PORT=5588

CMD ["npm", "run", "start:server"]
