# Build stage - includes development tools
FROM debian:12 AS builder
MAINTAINER Christophe Combelles. <ccomb@prelab.fr>

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        curl \
        ca-certificates \
        git \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# Install uv
ADD https://astral.sh/uv/install.sh /uv-installer.sh
RUN sh /uv-installer.sh && rm /uv-installer.sh
ENV PATH="/root/.local/bin/:$PATH"

COPY buttervolume.zip /
RUN mkdir /usr/src/buttervolume \
    && unzip -d /usr/src/buttervolume buttervolume.zip \
    && cd /usr/src/buttervolume \
    && uv pip install --target /app .

# Runtime stage - minimal dependencies
FROM debian:12
MAINTAINER Christophe Combelles. <ccomb@prelab.fr>

RUN set -x; \
    apt-get update \
    && apt-get install -y --no-install-recommends \
        btrfs-progs \
        curl \
        ca-certificates \
        python3 \
        python3-pip \
        ssh \
        rsync \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/docker/plugins \
    && mkdir -p /var/lib/buttervolume/volumes \
    && mkdir -p /var/lib/buttervolume/snapshots \
    && mkdir /etc/buttervolume /root/.ssh

# Copy the built application from builder stage
COPY --from=builder /app /usr/local/lib/python3.11/site-packages/
ENV PYTHONPATH=/usr/local/lib/python3.11/site-packages

# add tini to avoid sshd zombie processes
ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini

COPY entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
CMD ["run"]
