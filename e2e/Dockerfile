# One image for every node in the e2e stack: the gateway binary plus network test tools.
FROM rust:1.96-trixie AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends libclang-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release && cp target/release/drawbridge /usr/local/bin/

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends nftables iproute2 netcat-openbsd iputils-ping procps socat \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/drawbridge /usr/local/bin/
COPY e2e/entrypoint.sh /usr/local/bin/
ENTRYPOINT ["entrypoint.sh"]
