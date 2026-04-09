FROM debian:bookworm-slim

ENV AGENTFENCE_HOME="/agentfence/home"
ENV HOME="${AGENTFENCE_HOME}"
ENV PATH="${AGENTFENCE_HOME}/.local/bin:${PATH}"

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

RUN mkdir -p /workspace /agentfence/ssh /agentfence/creds /agentfence/home /var/log/agentfence \
    && chmod 0755 /agentfence/home

WORKDIR /workspace

COPY audit_log.py /usr/local/bin/agentfence-audit
COPY registry_update.py /usr/local/bin/agentfence-registry
COPY file_watcher.py /usr/local/bin/agentfence-file-watcher
COPY workspace_watcher.py /usr/local/bin/agentfence-workspace-watcher
COPY network_watcher.py /usr/local/bin/agentfence-network-watcher
COPY bash_env.sh /agentfence/bash_env.sh
COPY bashrc /agentfence/bashrc
COPY entrypoint.sh /usr/local/bin/agentfence-entrypoint
RUN chmod +x /usr/local/bin/agentfence-entrypoint /usr/local/bin/agentfence-audit /usr/local/bin/agentfence-registry /usr/local/bin/agentfence-file-watcher /usr/local/bin/agentfence-workspace-watcher /usr/local/bin/agentfence-network-watcher

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/agentfence-entrypoint"]
CMD ["/bin/bash"]
