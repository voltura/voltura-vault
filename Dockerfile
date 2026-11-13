FROM rust:1.99.1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --locked --release --bin voltura-vault-server

FROM debian:bookworm-slim
RUN install -d -m 0700 -o 10001 -g 10001 /var/lib/voltura
COPY --from=build /src/target/release/voltura-vault-server /usr/local/bin/
USER 10001:10001
STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/local/bin/voltura-vault-server"]
CMD ["run", "/var/lib/voltura/data"]
