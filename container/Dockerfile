FROM debian:bookworm-slim

ENV FISHBOWL_HOME="/fishbowl/home"
ENV HOME="${FISHBOWL_HOME}"
ENV PATH="${FISHBOWL_HOME}/.local/bin:${PATH}"

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash \
        bubblewrap \
        ca-certificates \
        coreutils \
        curl \
        git \
        inotify-tools \
        iproute2 \
        iptables \
        jq \
        nodejs \
        npm \
        openssh-client \
        procps \
        psmisc \
        python3 \
        python3-pip \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Install the validated agent CLIs into the image. The Linux host-mount path
# in `container.rs::auto_discovered_agent_runtime_mounts` bind-mounts the host's
# npm-installed native binary on top of these on Linux hosts, so this baseline
# is what gets used on macOS hosts (which can't share their host binary because
# it's a Mach-O binary, not a Linux ELF). Pinning is intentionally avoided so
# `fishbowl build-image` picks up the latest published agent each rebuild.
RUN npm install -g @openai/codex @anthropic-ai/claude-code \
    && npm cache clean --force \
    && command -v codex >/dev/null && command -v claude >/dev/null

RUN mkdir -p /workspace /fishbowl/ssh /fishbowl/creds /fishbowl/home /var/log/fishbowl \
    && chmod 0755 /fishbowl/home

WORKDIR /workspace

COPY audit_log.py /usr/local/bin/fishbowl-audit
COPY registry_update.py /usr/local/bin/fishbowl-registry
COPY file_watcher.py /usr/local/bin/fishbowl-file-watcher
COPY workspace_watcher.py /usr/local/bin/fishbowl-workspace-watcher
COPY network_watcher.py /usr/local/bin/fishbowl-network-watcher
COPY bash_env.sh /fishbowl/bash_env.sh
COPY bashrc /fishbowl/bashrc
COPY entrypoint.sh /usr/local/bin/fishbowl-entrypoint
RUN chmod +x /usr/local/bin/fishbowl-entrypoint /usr/local/bin/fishbowl-audit /usr/local/bin/fishbowl-registry /usr/local/bin/fishbowl-file-watcher /usr/local/bin/fishbowl-workspace-watcher /usr/local/bin/fishbowl-network-watcher

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/fishbowl-entrypoint"]
CMD ["/bin/bash"]
