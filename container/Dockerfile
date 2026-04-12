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
