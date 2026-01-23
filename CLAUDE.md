# N42 Node Project Memory

## 项目概述

N42 是一个基于 Reth 的 POA (Proof of Authority) 区块链节点，采用 CL/EL 分离架构：
- **N42 (共识层)**: POA 共识、Beacon 状态管理、区块生产
- **Reth (执行层)**: EVM 执行、状态存储、交易池

## 架构设计

```
┌─────────────────────────────────────────┐
│           N42 (Beacon Layer)            │
│  • BeaconBlockTree (内存，最近64块)      │
│  • CliqueForkChoice (基于 TD)           │
│  • ReorgExecutor (协调 reorg)           │
├─────────────────────────────────────────┤
│           Engine API (FCU)              │
├─────────────────────────────────────────┤
│           Reth (Execution Layer)        │
│  • EVM 状态自动回滚                      │
│  • 交易池管理                           │
└─────────────────────────────────────────┘
```

## 关键设计决策

1. **Reorg 分层处理**: N42 只处理 Beacon 层 reorg，执行层 reorg 通过 `forkchoiceUpdated` 委托给 Reth
2. **内存区块树**: 最近 64 块保留内存，支持多分叉，超过后持久化到 BeaconStore
3. **Fork Choice**: 基于 Clique 的 total difficulty，相同 TD 时低 hash 获胜

## 模块结构

```
src/consensus/
├── block_tree.rs    # 内存区块树，支持多分叉
├── fork_choice.rs   # Fork choice 逻辑 (TD 比较)
├── reorg.rs         # Reorg 执行器
├── clique/          # Clique POA 共识
├── state.rs         # BeaconState
└── worker.rs        # 区块生产 worker

src/miner/           # 出块逻辑，wiggle delay
src/storage/         # BeaconStore (内存/持久化)
src/engine/          # Engine API 类型
src/primitives/      # SignedBeaconBlock, UnifiedBlock
```

## 常用命令

```bash
# 编译检查
cargo check

# 运行测试
cargo test --lib

# 运行 POA 演示节点
cargo run --bin poa_eth66 -- --validator-index 0 --port 30303
```

## 注意事项

- `difficulty` 字段不参与 `block_root()` 计算（在 BeaconBlockHeader 中）
- 测试中需要用不同的 `state_root` 来区分相同 difficulty 的区块
