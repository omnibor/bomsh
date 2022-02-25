# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.217.1/containers/cpp/.devcontainer/base.Dockerfile

# [Choice] Debian / Ubuntu version (use Debian 11, Ubuntu 18.04/21.04 on local arm64/Apple Silicon): debian-11, debian-10, ubuntu-21.04, ubuntu-20.04, ubuntu-18.04
ARG VARIANT="bullseye"
FROM mcr.microsoft.com/vscode/devcontainers/cpp:0-${VARIANT} as base

FROM base as bash
WORKDIR /home/vscode
RUN git clone https://github.com/bminor/bash.git
WORKDIR /home/vscode/bash
RUN ./configure && make
COPY ./patches/bombash.patch .

FROM base as strace
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends bison autoconf automake autotools-dev
WORKDIR /home/vscode
RUN git clone https://github.com/strace/strace.git
WORKDIR /home/vscode/strace
RUN ./bootstrap && ./configure --enable-mpers=check && make
COPY ./patches/bomtrace.patch ./patches/bomtrace2.patch ./

FROM bash as bomsh
RUN patch -p1 < bombash.patch
RUN make

FROM strace as bomtrace
RUN patch -p1 < bomtrace.patch
RUN make

FROM strace as bomtrace2
RUN patch -p1 < bomtrace2.patch
RUN make

FROM base as copy
WORKDIR /in
COPY --from=bomsh /home/vscode/bash/bash ./bomsh
COPY --from=bomtrace /home/vscode/strace/src/strace ./bomtrace
COPY --from=bomtrace2 /home/vscode/strace/src/strace ./bomtrace2
CMD cp * /out