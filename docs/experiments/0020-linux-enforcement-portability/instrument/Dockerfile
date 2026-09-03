FROM python:3.12.11-bookworm@sha256:13c9584604a99ca134c4f41800f74ffc64ee6ac8cf555cf1e704a6087fc84f12

RUN apt-get update \
    && apt-get install --yes --no-install-recommends gcc libc6-dev nodejs rustc \
    && rm -rf /var/lib/apt/lists/*

COPY linux_enforcer.c /tmp/linux_enforcer.c
RUN cc -std=c11 -O2 -Wall -Wextra -Werror \
    /tmp/linux_enforcer.c -o /usr/local/bin/proofbound-linux-enforcer \
    && rm /tmp/linux_enforcer.c

ENTRYPOINT ["/usr/bin/sleep", "infinity"]
