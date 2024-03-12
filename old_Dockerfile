FROM opensuse/tumbleweed:latest AS ref_repo

RUN sed -i -E 's/https?:\/\/download.opensuse.org/https:\/\/mirrorcache.firstyear.id.au/g' /etc/zypp/repos.d/*.repo && \
    zypper --gpg-auto-import-keys ref --force

# // setup the builder pkgs
FROM ref_repo AS build_base
RUN zypper install -y cargo rust gcc libopenssl-3-devel sccache perl make gawk

# // setup the runner pkgs
FROM ref_repo AS run_base
RUN zypper install -y sqlite3 openssl-3 timezone iputils iproute2 openldap2-client
COPY SUSE_CA_Root.pem /etc/pki/trust/anchors/
RUN /usr/sbin/update-ca-certificates

# // build artifacts
FROM build_base AS builder

COPY . /home/proxy/
RUN mkdir /home/proxy/.cargo
COPY cargo_config /home/proxy/.cargo/config
WORKDIR /home/proxy/opensuse-proxy-cache

# RUSTFLAGS="-Ctarget-cpu=x86-64-v3"
#
# 

RUN if [ "$(uname -i)" = "x86_64" ]; then export RUSTFLAGS="-Ctarget-cpu=x86-64-v3 --cfg tokio_unstable"; fi && \
    SCCACHE_REDIS=redis://redis.firstyear.id.au:6379 \
    RUSTC_WRAPPER=sccache \
    RUST_BACKTRACE=full \
    cargo build --release

# == end builder setup, we now have static artifacts.
FROM run_base
MAINTAINER william@blackhats.net.au
EXPOSE 636
WORKDIR /

COPY --from=builder /home/proxy/target/release/ldap-proxy /bin/

STOPSIGNAL SIGINT

ENV RUST_BACKTRACE 1
CMD ["/bin/ldap-proxy", "-c", "/data/config.toml"]
