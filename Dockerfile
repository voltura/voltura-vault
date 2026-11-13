FROM rust:1.99.1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --locked --release --bin voltura-vault-server

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN install -d -m 0700 -o 10001 -g 10001 /var/lib/voltura
COPY --from=build /src/target/release/voltura-vault-server /usr/local/bin/
USER 10001:10001
STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/local/bin/voltura-vault-server"]
CMD ["run", "/var/lib/voltura/data"]
