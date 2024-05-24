FROM clux/muslrust:stable as chef
 
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build & cache dependencies

RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json
# Copy source code from previous stage
COPY . .
# Build application
RUN cargo build --release --target x86_64-unknown-linux-musl --bin ldap-proxy


FROM gcr.io/distroless/cc AS runtime
#WORKDIR /usr/local/bin/app
COPY --from=planner /app/Config.toml /config/Config.toml
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/ldap-proxy /usr/local/bin/app

EXPOSE 9389
CMD ["/usr/local/bin/app","-c","/config/Config.toml"]