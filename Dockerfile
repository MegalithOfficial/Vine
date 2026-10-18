FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev git
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY wit ./wit

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked && \
    cp target/release/vine /usr/local/bin/vine

FROM alpine:3.24

COPY --from=builder /usr/local/bin/vine /usr/local/bin/vine

RUN addgroup -g 2613 vine && \
    adduser -u 2613 -G vine -D -h /vine vine && \
    chown -R vine:vine /vine

WORKDIR /vine
USER vine:vine

ENV RUST_BACKTRACE=1
EXPOSE 25565

ENTRYPOINT [ "vine" ]

# Checks the port Vine actually binds: VINE_BIND_ADDRESS if set, otherwise [server] bind_address in
# vine.toml
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD addr="$(printf '%s' "${VINE_BIND_ADDRESS:-}" | tr -d ' \t')"; \
        [ -n "$addr" ] || addr="$(awk '/^[ \t]*\[/ { s = $0; gsub(/[ \t]/, "", s); section = s; next } \
            section == "[server]" && /^[ \t]*bind_address[ \t]*=/ { v = $0; sub(/^[^=]*=/, "", v); \
            sub(/#.*/, "", v); gsub(/[ \t"\047]/, "", v); print v; exit }' /vine/vine.toml)"; \
        port="${addr##*:}"; \
        nc -z 127.0.0.1 "${port:-25565}" || exit 1
