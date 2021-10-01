#!/usr/bin/env bash

set -euo pipefail

install_rustup() {
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    rustup toolchain install nightly
    rustup default nightly
    cargo --version
    rustc --version
}

main() {
    sudo apt-get update && sudo apt-get install -y gcc curl ca-certificates \
        libnspr4-dev libnss3-dev
    install_rustup
    pushd ..
        git clone https://github.com/rustls/rustls-ffi
        pushd rustls-ffi
            make
            sudo make install
        popd
    popd
    LDFLAGS="-L/usr/lib/x86_64-linux-gnu -L/usr/lib/x86_64-linux-gnu/nspr -L/usr/local/lib" CPPFLAGS="-I/usr/include/nss -I/usr/include/nspr -I/usr/local/include" ./configure --with-ssl=rustls
    make
    sudo make install
    make check
    pushd src/test/ssl
        make check
    popd
}

main "$@"
