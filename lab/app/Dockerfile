# Single image, version-parameterized at build time:
#   docker build --build-arg BANDIT_VERSION=1.10.4 -t lab-app:1.10.4 .
#   docker build --build-arg BANDIT_VERSION=1.14.1 -t lab-app:1.14.1 .
# This guarantees the vulnerable and patched containers are byte-for-byte
# identical apart from the pinned Bandit dependency, which is the whole
# point of an A/B lab experiment.
FROM hexpm/elixir:1.17.3-erlang-27.1.2-debian-bookworm-20241202-slim@sha256:318497672d700b95c95a3195549e30c8451ab7e6eb5f462415653b94ab1032b6 AS build

ARG BANDIT_VERSION=1.14.1
ENV BANDIT_VERSION=${BANDIT_VERSION}
ENV MIX_ENV=prod
# OTP 27 auto-sizes max_ports (and thus the fixed port_table) up to 2^24 on
# high-memory hosts -- that alone reserves ~1.5 GiB at VM startup. Every
# `mix` command starts a fresh BEAM, so without this cap the build stage and
# the 512 MiB runtime containers are OOM-killed before any app code runs.
# 262144 ports is far above anything the lab needs. It also keeps the VM
# baseline small enough that a PoC's memory amplification is the signal
# under test rather than host-memory-derived noise.
ENV ERL_AFLAGS="+Q 262144"

RUN apt-get update -y && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mix local.hex --force && mix local.rebar --force

WORKDIR /app
COPY mix.exs mix.exs
COPY config config
# Per-version lockfiles keep `mix deps.get` deterministic across the three
# pinned Bandit releases. The lockfile is selected by the same build arg that
# pins Bandit in mix.exs.
COPY locks locks
RUN cp "locks/mix-${BANDIT_VERSION}.lock" mix.lock
RUN mix deps.get --only prod
RUN mix deps.compile

COPY lib lib
RUN mix compile

FROM hexpm/elixir:1.17.3-erlang-27.1.2-debian-bookworm-20241202-slim@sha256:318497672d700b95c95a3195549e30c8451ab7e6eb5f462415653b94ab1032b6 AS runtime

ARG BANDIT_VERSION=1.14.1
ENV BANDIT_VERSION=${BANDIT_VERSION}
ENV MIX_ENV=prod
ENV MIX_HOME=/app/.mix
ENV HEX_HOME=/app/.hex
ENV HOME=/tmp
# Same OTP 27 max_ports cap as the build stage: without it the fixed
# port_table reserves ~1.5 GiB and the 512 MiB container is killed before
# the application starts.
ENV ERL_AFLAGS="+Q 262144"

# Isolated, unprivileged runtime user -- the whole point of this container
# is to absorb hostile traffic during resource-exhaustion experiments.
RUN useradd -m labapp
WORKDIR /app
COPY --from=build /app /app
# Install Hex/Rebar under MIX_HOME, not the root user's home, so the labapp
# user can still read them after USER. --no-compile/--no-deps-check below
# keep `mix run` from trying to write to the read-only root filesystem.
RUN mix local.hex --force && mix local.rebar --force \
    && chown -R labapp:labapp /app
USER labapp

EXPOSE 4000 4001
CMD ["mix", "run", "--no-compile", "--no-deps-check", "--no-halt"]
