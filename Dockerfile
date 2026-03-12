FROM rust:1.94 as builder

WORKDIR /usr/src/app

COPY Cargo.toml Cargo.lock* ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/app/target/release/age-inbox /usr/local/bin/age-inbox

RUN mkdir -p /app/vaults
ENV VAULTS_DIR=/app/vaults

EXPOSE 3000

CMD ["age-inbox"]
