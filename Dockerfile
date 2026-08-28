# Build stage - includes development tools
FROM alpine:3.22 AS builder
MAINTAINER Christophe Combelles. <ccomb@free.fr>

RUN apk add --no-cache \
        python3 \
        uv \
        ca-certificates \
        unzip

COPY buttervolume.zip /
RUN mkdir -p /usr/src/buttervolume \
    && unzip -d /usr/src/buttervolume buttervolume.zip \
    && cd /usr/src/buttervolume \
    && uv pip install --target /app .

# Runtime stage - minimal dependencies
FROM alpine:3.22
LABEL maintainer="Christophe Combelles <ccomb@free.fr>"

# Install runtime dependencies and create directories in one layer
# e2fsprogs-extra puts the reference chattr and lsattr where busybox otherwise
# leaves its own smaller ones, so the copy on write flag is set by the same
# tool as before
# tini keeps sshd from leaving zombie processes behind
# The ssh host keys are made here rather than at startup, as the Debian package
# used to make them, so that restarting the plugin does not change the identity
# the hosts replicating to it already know
RUN apk add --no-cache \
        btrfs-progs \
        e2fsprogs-extra \
        ca-certificates \
        python3 \
        py3-pytest \
        py3-webtest \
        openssh \
        openssh-client \
        rsync \
        tini \
    && mkdir -p /run/docker/plugins \
    && mkdir -p /var/lib/buttervolume/volumes \
    && mkdir -p /var/lib/buttervolume/snapshots \
    && mkdir -p /etc/buttervolume /root/.ssh \
    && ssh-keygen -A

# Copy the built application from builder stage
COPY --from=builder /app /app
ENV PYTHONPATH=/app
ENV PATH="/app/bin:$PATH"

COPY entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
CMD ["run"]
