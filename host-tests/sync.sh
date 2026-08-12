#!/bin/bash
# 从 agent 源同步 host-tests 副本（lz4_block/ghostmem）。
# 修改 agent 侧后运行本脚本再提交，防止副本漂移。
set -e
cd "$(dirname "$0")/.."
cp agent/src/trace/lz4_block.rs host-tests/src/lz4_block.rs
cp agent/src/ghostmem.rs host-tests/src/ghostmem.rs
echo "host-tests synced from agent"
