#!/usr/bin/env bash

set -euo pipefail

main() {
    ls -al
    ./configure
    make
}

main "$@"
