# Build stage - includes development tools
FROM debian:12 AS builder
MAINTAINER Christophe Combelles. <ccomb@prelab.fr>

RUN apt-get update
RUN apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        git \
        unzip
RUN rm -rf /var/lib/apt/lists/*
RUN python3 -m pip install --upgrade pip

COPY buttervolume.zip /
RUN mkdir /usr/src/buttervolume
RUN echo "Unzipping buttervolume.zip..." && unzip -d /usr/src/buttervolume buttervolume.zip
RUN echo "Contents after unzip:" && ls -la /usr/src/buttervolume/
RUN cd /usr/src/buttervolume && echo "Contents of source:" && ls -la
RUN cd /usr/src/buttervolume && echo "Installing with pip..." && python3 -m pip install --no-cache-dir --target /app . -v || (echo "Pip install failed, showing logs:" && cat ~/.cache/pip/log/* 2>/dev/null || echo "No pip logs found" && exit 1)

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
