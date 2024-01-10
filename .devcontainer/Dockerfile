# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.217.1/containers/cpp/.devcontainer/base.Dockerfile

# [Choice] Debian / Ubuntu version (use Debian 11, Ubuntu 18.04/21.04 on local arm64/Apple Silicon): debian-11, debian-10, ubuntu-21.04, ubuntu-20.04, ubuntu-18.04
ARG VARIANT="bullseye"
FROM mcr.microsoft.com/vscode/devcontainers/cpp:0-${VARIANT} as base

FROM base as strace
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends bison autoconf automake autotools-dev
WORKDIR /home/vscode
RUN git clone https://github.com/strace/strace.git
WORKDIR /home/vscode/strace
COPY ./patches/bomtrace2.patch ./patches/bomtrace3.patch ./
COPY ./src/*.[ch] src/

FROM strace as bomtrace2
WORKDIR /home/vscode/strace
RUN patch -p1 < bomtrace2.patch
RUN ./bootstrap && ./configure --enable-mpers=check && make

FROM strace as bomtrace3
WORKDIR /home/vscode/strace
RUN patch -p1 < bomtrace3.patch
RUN ./bootstrap && ./configure --enable-mpers=check && make

FROM base as copy
WORKDIR /in
COPY --from=bomtrace2 /home/vscode/strace/src/strace ./bomtrace2
COPY --from=bomtrace3 /home/vscode/strace/src/strace ./bomtrace3
CMD cp * /out
