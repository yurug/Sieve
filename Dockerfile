FROM golang:1.25-bookworm AS builder

WORKDIR /build

# Cache dependency downloads
COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o /sieve ./cmd/sieve

# Runtime image with batteries-included Python for policy scripts
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv (fast Python package manager) and set up Python environment
# with common packages useful for policy scripts.
#
# VPA-X01 drill finding #11: this whole block runs as root (USER sieve is
# set below, AFTER this), and `uv python install` with no
# UV_PYTHON_INSTALL_DIR resolves its default under
# $XDG_DATA_HOME/uv/python — which, with no XDG_DATA_HOME set and $HOME=
# /root, is /root/.local/share/uv/python/.... /opt/sieve-py/bin/python3 is
# a symlink into that path. /root is mode 0700 (root's home directory), so
# under `cap_drop: [ALL]` the non-root runtime user (sieve, uid 999) can't
# traverse into /root to follow the symlink — every script-mode policy
# fails closed with a permission error that looks like a missing
# interpreter, not a permissions bug. Pointing UV_PYTHON_INSTALL_DIR at
# /opt/uv-python (a path that was never under /root) fixes the traversal
# problem outright; the explicit chown below is belt-and-suspenders in
# case a future uv version or a different umask changes what gets created
# where.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
ENV UV_PYTHON_PREFERENCE=managed
ENV UV_PYTHON_INSTALL_DIR=/opt/uv-python
RUN uv python install 3.12 && \
    uv venv /opt/sieve-py && \
    . /opt/sieve-py/bin/activate && \
    uv pip install \
        # HTTP / API
        requests httpx \
        # Data
        pandas numpy \
        # LLM clients (for script-based policies that call LLMs)
        openai anthropic google-generativeai \
        # Parsing / formats
        beautifulsoup4 lxml pyyaml \
        # Auth / crypto
        pyjwt cryptography \
        # Text / regex
        regex \
        # JSON schema
        pydantic \
        # Templating
        jinja2 \
        # Token counting
        tiktoken
ENV PATH="/opt/sieve-py/bin:$PATH"

# Non-root user
RUN useradd -r -s /bin/false sieve && \
    mkdir -p /data /policies && \
    chown sieve:sieve /data /policies && \
    chown -R sieve:sieve /opt/uv-python /opt/sieve-py

COPY --from=builder /sieve /usr/local/bin/sieve

USER sieve

VOLUME ["/data"]
VOLUME ["/policies"]

EXPOSE 19816 19817

ENTRYPOINT ["sieve"]
CMD ["serve"]
