#! /usr/bin/env bash
#
# Prepare the worktree for a pull request.
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

set -e

tools_dir=$(dirname -- "$0")

bash -e "${tools_dir}/format.sh"
bash -e "${tools_dir}/copyright-update.sh"
