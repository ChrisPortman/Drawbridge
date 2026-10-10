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
      curl openssl \
 && rm -rf /var/lib/apt/lists/*
# The portal's certificate for the gateway's external address, from a test CA that clients trust
# with --ca-cert /etc/drawbridge/ca.crt (rustls refuses a CA certificate as a server's own).
RUN mkdir -p /etc/drawbridge && cd /etc/drawbridge \
 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -subj "/CN=Drawbridge e2e CA" -keyout ca.key -out ca.crt 2>/dev/null \
 && openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -subj /CN=172.30.0.2 -keyout portal.key -out portal.csr 2>/dev/null \
 && printf 'subjectAltName=IP:172.30.0.2\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n' >ext \
 && openssl x509 -req -in portal.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 \
      -extfile ext -out portal.crt 2>/dev/null \
 && rm ca.key portal.csr ext
# An unprivileged account for the client CLI and its (stubbed) user service.
RUN useradd -m -u 1000 user
COPY --from=build /usr/local/bin/drawbridge /usr/local/bin/
COPY e2e/entrypoint.sh e2e/systemctl-stub /usr/local/bin/
ENTRYPOINT ["entrypoint.sh"]
