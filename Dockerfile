# Two stages: build with the toolchain, ship without it.
#
# The result is a distroless image running as a non-root user with no shell,
# no package manager and nothing to write. It holds one binary, dynamically
# linked against glibc -- which is why the base is the `cc` variant rather than
# `static`. The stylesheet is compiled in, so there is no asset directory.
#
# Both bases are pinned by digest, so a tag moved upstream changes nothing
# here. Bump the digests to take the base images' security fixes.

FROM rust:1.88-slim@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS build
WORKDIR /src

# Dependencies first, so editing source does not re-download the tree.
COPY Cargo.toml Cargo.lock ./
COPY crates/monerod-rpc/Cargo.toml crates/monerod-rpc/
COPY crates/explorer-core/Cargo.toml crates/explorer-core/
COPY crates/explorer-web/Cargo.toml crates/explorer-web/
RUN mkdir -p crates/monerod-rpc/src crates/explorer-core/src crates/explorer-web/src \
 && echo 'fn main() {}' > crates/explorer-web/src/main.rs \
 && touch crates/monerod-rpc/src/lib.rs crates/explorer-core/src/lib.rs \
 && cargo build --release --locked 2>/dev/null || true

COPY . .
# The placeholder above leaves stale artifacts; force a real rebuild of ours.
RUN touch crates/*/src/lib.rs crates/explorer-web/src/main.rs \
 && cargo build --release --locked -p explorer-web

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /src/target/release/oxblocks /usr/local/bin/oxblocks

# Binds inside the container; publish it with -p. Defaults to loopback, which
# would be unreachable from outside the container, so this is set explicitly.
EXPOSE 8081
# Numeric, so that a runtime enforcing non-root can tell without a passwd file.
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/oxblocks"]
CMD ["--bind", "0.0.0.0:8081", "--daemon-url", "http://host.docker.internal:18081"]
