FROM quay.io/rockylinux/rockylinux:9

RUN dnf -y update && dnf -y install vim-common && rm -rf /var/cache/dnf/*
RUN mkdir -p /migrations /bundle
COPY peridot/migrate/*.sql /migrations
COPY bazel-build/peridotserver /bundle/peridotserver
RUN chmod 0755 /bundle/peridotserver
