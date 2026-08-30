# Both stages have to carry the same interpreter: the build stage stages the
# install under lib/pythonX.Y and the runtime copies it into /usr, where python
# reads the directory named after its own version. Naming the base once is what
# keeps the two equal, so an upgrade stays the one line it was.
FROM alpine:3.22 AS base

# Build stage - includes development tools
FROM base AS builder
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
    && uv pip install --prefix /staging '.[test]'

# Runtime stage - minimal dependencies
FROM base
LABEL maintainer="Christophe Combelles <ccomb@free.fr>"

# Install runtime dependencies and create directories in one layer
# e2fsprogs-extra puts the reference chattr and lsattr where busybox otherwise
# leaves its own smaller ones, so the copy on write flag is set by the same
# tool as before
# tini keeps sshd from leaving zombie processes behind
# Python packages come from the build stage only, never from apk as well: the
# copy below writes into the directory apk installs into, so a package owned by
# both would end up half from one version and half from the other
# No ssh host key is made here: the image is public, so a key baked into it
# would be the same on every installation that pulls it. The entrypoint makes
# them on the first start, in the directory that survives a restart
RUN apk add --no-cache \
        btrfs-progs \
        e2fsprogs-extra \
        ca-certificates \
        python3 \
        openssh \
        openssh-client \
        rsync \
        tini \
    && mkdir -p /run/docker/plugins \
    && mkdir -p /var/lib/buttervolume/volumes \
    && mkdir -p /var/lib/buttervolume/snapshots \
    && mkdir -p /etc/buttervolume /root/.ssh

# Copy the built application from the builder stage into the paths python and
# the shell already look at. A docker plugin is not started from the image
# configuration, so an install somewhere else would need a PATH and a
# PYTHONPATH that only the entrypoint could set, and every "runc exec" into the
# running plugin would miss them.
COPY --from=builder /staging/bin /usr/bin
COPY --from=builder /staging/lib /usr/lib

COPY entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
CMD ["run"]
