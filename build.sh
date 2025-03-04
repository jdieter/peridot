#!/bin/bash
set -e
bazelisk build //peridot/cmd/v1/peridotserver:peridotserver
bazelisk build //peridot/cmd/v1/keykeeper:keykeeper
mkdir -p bazel-build
rm -f bazel-build/*
cp -a bazel-bin/peridot/cmd/v1/peridotserver/peridotserver_/peridotserver bazel-build/
cp -a bazel-bin/peridot/cmd/v1/keykeeper/keykeeper_/keykeeper bazel-build/
docker build -t peridotserver -f containers/peridotserver/Dockerfile .
docker build -t keykeeper -f containers/keykeeper/Dockerfile .
