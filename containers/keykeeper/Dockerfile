FROM quay.io/rockylinux/rockylinux:9

ENV TINI_VERSION=v0.19.0

RUN curl -o /tini -L "https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')"
RUN chmod +x /tini
RUN dnf -y update \
    && dnf -y install epel-release \
    && dnf -y install \
        bash \
        bzip2 \
        cpio \
        diffutils \
        findutils \
        gawk \
        gcc \
        gcc-c++ \
        git \
        grep \
        gzip \
        info \
        make \
        patch \
        python3 \
        redhat-rpm-config \
        rpm-build \
        scl-utils-build \
        sed \
        shadow-utils \
        tar \
        unzip \
        util-linux \
        which \
        xz \
        dnf-plugins-core \
        createrepo_c \
        rpm-sign \
        sudo \
        mock \
        mock-rpmautospec \
    && rm -rf /var/cache/dnf/*
RUN useradd -o -d /var/peridot -u 1002 peridotbuilder && usermod -a -G mock peridotbuilder
RUN chown peridotbuilder:mock /etc/yum.conf && chown -R peridotbuilder:mock /etc/dnf && chown -R peridotbuilder:mock /etc/rpm && chown -R peridotbuilder:mock /etc/yum.repos.d
RUN mkdir -p /bundle
COPY bazel-build/keykeeper /bundle/keykeeper
RUN chmod 0755 /bundle/keykeeper
USER peridotbuilder
ENTRYPOINT ["/tini", "--"]
