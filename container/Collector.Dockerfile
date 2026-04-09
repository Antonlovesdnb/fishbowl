FROM rust:1.86-alpine AS builder

WORKDIR /src
RUN apk add --no-cache musl-dev gcc

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM alpine:3.22

RUN apk add --no-cache \
    bash \
    bpftrace \
    coreutils \
    docker-cli \
    iproute2 \
    jq

COPY --from=builder /src/target/release/agentfence /usr/local/bin/agentfence

ENTRYPOINT ["/usr/local/bin/agentfence"]
