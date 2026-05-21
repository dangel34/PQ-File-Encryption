FROM gcr.io/oss-fuzz-base/base-builder-rust # NOSONAR docker:S6596 - OSS-Fuzz base images ship no versioned tags; Google manages the lifecycle

# OSS-Fuzz build infrastructure requires root; this is intentional.
USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock $SRC/pqfile/
COPY pqfile/ $SRC/pqfile/pqfile/
COPY fuzz/ $SRC/pqfile/fuzz/
WORKDIR $SRC/pqfile
COPY oss-fuzz/build.sh $SRC/
