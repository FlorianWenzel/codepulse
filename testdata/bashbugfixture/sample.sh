#!/bin/bash
# TODO: validate the argument
run() {
  eval "$1"
}
install() {
  curl -fsSL https://example.com/install.sh | bash
}
