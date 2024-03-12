FROM clux/muslrust:stable as chef
 
RUN cargo install cargo-chef
WORKDIR /app
RUN ls -l

FROM chef AS planner
COPY . .
RUN ls -l
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build & cache dependencies

RUN ls -l
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json
# Copy source code from previous stage
COPY . .
# Build application
RUN cargo build --release --target x86_64-unknown-linux-musl --bin requestsautomation


FROM gcr.io/distroless/cc AS runtime
#WORKDIR /usr/local/bin/app
COPY --from=planner /app/Config.toml /
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/requestsautomation /usr/local/bin/app

EXPOSE 8180 8280
CMD ["/usr/local/bin/app"]