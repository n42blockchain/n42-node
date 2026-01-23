# N42 Beacon 层 Reorg 实现计划

## 背景

N42 采用 CL/EL 分离架构：
- **N42 (共识层)**: 负责 POA 共识、Beacon 状态管理
- **Reth (执行层)**: 负责 EVM 执行、状态存储、交易池

当 N42 检测到需要 reorg 时，只需：
1. 处理 Beacon 层的链切换
2. 通过 `forkchoiceUpdated` 通知 Reth，Reth 自动处理执行层 reorg

## 核心设计：内存区块树

采用类似 Reth TreeState 的设计：

```
┌─────────────────────────────────────────────────────────────┐
│                    内存区块树 (最近 64 块)                   │
│                                                             │
│                         [B60]                               │
│                           │                                 │
│                         [B61]                               │
│                           │                                 │
│                         [B62]──────┐                        │
│                           │        │                        │
│     canonical chain →   [B63]    [B62']  ← 侧链             │
│                           │        │                        │
│                         [B64]    [B63']                     │
│                           │                                 │
│                         [B65] ← head                        │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│        超过 64 块深度 → 持久化到磁盘，从内存移除             │
└─────────────────────────────────────────────────────────────┘
```

**核心原则**：
- 最近 64 个区块保留在内存
- 支持多条侧链共存
- 64 块内可任意切换规范链
- BeaconState 从区块树按需重建（状态简单，无需检查点）

## 模块设计

### 模块 1: BeaconBlockTree

**文件**: `src/consensus/block_tree.rs`

```rust
/// 内存中的区块树，维护最近的区块和所有已知分叉
pub struct BeaconBlockTree {
    /// 所有已知区块 (hash -> block)
    blocks: HashMap<B256, SignedBeaconBlock>,

    /// 按 slot 索引 (slot -> [hashes])，同一 slot 可能有多个区块
    blocks_by_slot: BTreeMap<u64, Vec<B256>>,

    /// 父子关系 (parent_hash -> [child_hashes])
    children: HashMap<B256, HashSet<B256>>,

    /// 当前规范链头
    canonical_head: B256,

    /// 已持久化的最高 slot（此 slot 及之前的区块可从磁盘读取）
    finalized_slot: u64,

    /// 保留的区块深度
    retention_depth: u64,  // 默认 64
}

impl BeaconBlockTree {
    /// 插入新区块
    pub fn insert(&mut self, block: SignedBeaconBlock) -> Result<()>;

    /// 获取区块
    pub fn get(&self, hash: &B256) -> Option<&SignedBeaconBlock>;

    /// 获取规范链头
    pub fn canonical_head(&self) -> &SignedBeaconBlock;

    /// 设置新的规范链头（用于 reorg）
    pub fn set_canonical_head(&mut self, hash: B256);

    /// 找到两个区块的共同祖先
    pub fn find_common_ancestor(&self, a: B256, b: B256) -> Option<B256>;

    /// 获取从 ancestor 到 descendant 的区块路径
    pub fn get_chain(&self, from: B256, to: B256) -> Vec<SignedBeaconBlock>;

    /// 计算链的 total difficulty
    pub fn total_difficulty(&self, head: B256) -> u64;

    /// 清理旧区块（持久化并移除）
    pub fn prune(&mut self, below_slot: u64) -> Vec<SignedBeaconBlock>;
}
```

### 模块 2: ForkChoice

**文件**: `src/consensus/fork_choice.rs`

```rust
/// Fork choice 决策结果
pub enum ForkChoiceDecision {
    /// 区块扩展当前规范链
    Extend { block: B256 },

    /// 需要切换到新链
    Reorg {
        /// 共同祖先
        common_ancestor: B256,
        /// 旧链要移除的区块 (从 ancestor 之后到旧 head)
        old_blocks: Vec<SignedBeaconBlock>,
        /// 新链要应用的区块 (从 ancestor 之后到新 head)
        new_blocks: Vec<SignedBeaconBlock>,
    },

    /// 区块来自弱链，保留但不切换
    Keep { block: B256 },
}

/// Clique POA fork choice 规则
pub struct CliqueForkChoice;

impl CliqueForkChoice {
    /// 评估新区块，决定是否需要 reorg
    pub fn evaluate(
        tree: &BeaconBlockTree,
        new_block: &SignedBeaconBlock,
    ) -> ForkChoiceDecision {
        let current_head = tree.canonical_head();
        let new_hash = new_block.block_root();
        let parent_hash = new_block.parent_hash();

        // Case 1: 扩展当前链
        if parent_hash == current_head.block_root() {
            return ForkChoiceDecision::Extend { block: new_hash };
        }

        // Case 2: 分叉，比较 total difficulty
        let current_td = tree.total_difficulty(current_head.block_root());
        let new_td = tree.total_difficulty(new_hash);

        if new_td > current_td || (new_td == current_td && new_hash < current_head.block_root()) {
            // 新链更强，执行 reorg
            let ancestor = tree.find_common_ancestor(current_head.block_root(), new_hash)?;
            ForkChoiceDecision::Reorg {
                common_ancestor: ancestor,
                old_blocks: tree.get_chain(ancestor, current_head.block_root()),
                new_blocks: tree.get_chain(ancestor, new_hash),
            }
        } else {
            // 当前链更强，保留新区块但不切换
            ForkChoiceDecision::Keep { block: new_hash }
        }
    }
}
```

**Fork Choice 规则**:
1. Total difficulty 更高的链获胜
2. Difficulty 相等时，block hash 更小的获胜（确定性）
3. 超过 64 块深度的 reorg 被拒绝

### 模块 3: ReorgExecutor

**文件**: `src/consensus/reorg.rs`

```rust
/// Reorg 执行统计
pub struct ReorgStats {
    pub common_ancestor_slot: u64,
    pub blocks_reverted: usize,
    pub blocks_applied: usize,
    pub new_head: B256,
}

/// Reorg 执行器
pub struct ReorgExecutor {
    /// Engine API 客户端（通知 Reth）
    engine_client: Option<EngineApiClient>,
}

impl ReorgExecutor {
    /// 执行 reorg
    pub async fn execute(
        &self,
        tree: &mut BeaconBlockTree,
        decision: ForkChoiceDecision,
    ) -> Result<Option<ReorgStats>> {
        match decision {
            ForkChoiceDecision::Extend { block } => {
                tree.set_canonical_head(block);
                self.notify_new_head(block).await?;
                Ok(None)
            }

            ForkChoiceDecision::Keep { .. } => {
                // 区块已在树中，无需操作
                Ok(None)
            }

            ForkChoiceDecision::Reorg { common_ancestor, old_blocks, new_blocks } => {
                // 1. 更新规范链头
                let new_head = new_blocks.last().unwrap().block_root();
                tree.set_canonical_head(new_head);

                // 2. 通知 Reth 执行 reorg
                self.notify_forkchoice_updated(new_head, common_ancestor).await?;

                Ok(Some(ReorgStats {
                    common_ancestor_slot: tree.get(&common_ancestor)?.slot(),
                    blocks_reverted: old_blocks.len(),
                    blocks_applied: new_blocks.len(),
                    new_head,
                }))
            }
        }
    }

    /// 通知 Reth 新的链头
    async fn notify_new_head(&self, head: B256) -> Result<()>;

    /// 通知 Reth forkchoice 更新（触发执行层 reorg）
    async fn notify_forkchoice_updated(&self, head: B256, finalized: B256) -> Result<()>;
}
```

## 区块处理完整流程

```rust
/// 处理新收到的区块
async fn on_new_block(&mut self, block: SignedBeaconBlock) -> Result<()> {
    // 1. 基础验证（签名、slot、proposer）
    self.validate_block(&block)?;

    // 2. 插入区块树
    self.block_tree.insert(block.clone())?;

    // 3. Fork choice 评估
    let decision = CliqueForkChoice::evaluate(&self.block_tree, &block);

    // 4. 执行决策（可能触发 reorg）
    if let Some(stats) = self.reorg_executor.execute(&mut self.block_tree, decision).await? {
        info!(
            "Reorg executed: reverted {} blocks, applied {} blocks, new head: {}",
            stats.blocks_reverted,
            stats.blocks_applied,
            stats.new_head
        );
    }

    // 5. 定期清理旧区块
    let finalized_slot = self.block_tree.canonical_head().slot().saturating_sub(64);
    let pruned = self.block_tree.prune(finalized_slot);
    if !pruned.is_empty() {
        self.persist_blocks(pruned).await?;
    }

    Ok(())
}
```

## 流程图

```
                        新区块到达
                            │
                            ▼
                    ┌───────────────┐
                    │   基础验证     │
                    │ (签名/slot等) │
                    └───────┬───────┘
                            │
                            ▼
                    ┌───────────────┐
                    │ 插入区块树    │
                    │ (保留侧链)    │
                    └───────┬───────┘
                            │
                            ▼
                    ┌───────────────┐
                    │  Fork Choice  │
                    │  评估 TD      │
                    └───────┬───────┘
                            │
            ┌───────────────┼───────────────┐
            │               │               │
            ▼               ▼               ▼
       ┌────────┐     ┌────────┐     ┌────────┐
       │ Extend │     │  Keep  │     │ Reorg  │
       │ 扩展链 │     │ 保留   │     │ 切换链 │
       └────┬───┘     └────┬───┘     └────┬───┘
            │              │              │
            │              │              ▼
            │              │      ┌──────────────┐
            │              │      │ 更新规范链头  │
            │              │      └──────┬───────┘
            │              │             │
            ▼              │             ▼
    ┌──────────────┐       │     ┌──────────────┐
    │ FCU → Reth   │       │     │ FCU → Reth   │
    │ (新 head)    │       │     │ (reorg)      │
    └──────────────┘       │     └──────────────┘
            │              │             │
            └──────────────┴─────────────┘
                           │
                           ▼
                   ┌───────────────┐
                   │  清理旧区块   │
                   │ (>64 持久化)  │
                   └───────────────┘
```

## 文件清单

### 新增文件
| 文件 | 说明 |
|------|------|
| `src/consensus/block_tree.rs` | 内存区块树 |
| `src/consensus/fork_choice.rs` | Fork choice 逻辑 |
| `src/consensus/reorg.rs` | Reorg 执行器 |

### 修改文件
| 文件 | 变更 |
|------|------|
| `src/consensus/mod.rs` | 导出新模块 |

## BeaconState 处理

由于 BeaconState 很简单，不需要检查点机制：

```rust
impl BeaconBlockTree {
    /// 重建指定区块的 BeaconState
    pub fn rebuild_state(&self, block_hash: B256) -> BeaconState {
        // 从创世或已知状态开始
        let mut state = self.genesis_state.clone();

        // 获取从创世到目标区块的路径
        let chain = self.get_canonical_chain_to(block_hash);

        // 依次应用区块
        for block in chain {
            process_block(&mut state, &block);
        }

        state
    }
}
```

实际上，对于 POA：
- `validators` 基本不变
- `slot` 直接从区块获取
- `latest_block_header` 直接从区块获取

所以大多数情况下不需要完整重建，直接从区块读取即可。

## 测试计划

### 单元测试

1. **BeaconBlockTree**
   - 插入单个区块
   - 插入分叉区块
   - find_common_ancestor 正确性
   - get_chain 正确性
   - total_difficulty 计算
   - prune 清理逻辑

2. **CliqueForkChoice**
   - Extend 场景
   - Keep 场景（弱链）
   - Reorg 场景（强链）
   - TD 相等时的 tie-breaker

3. **ReorgExecutor**
   - 正常 reorg 执行
   - Engine API 调用正确性

### 集成测试
- 模拟多节点网络分区后的 reorg 同步

## 配置项

```rust
pub struct BeaconConfig {
    /// 内存中保留的区块深度（默认 64）
    pub retention_depth: u64,

    /// 最大允许的 reorg 深度（默认 64）
    pub max_reorg_depth: u64,
}
```

## 已确认

1. ~~检查点机制~~ → 不需要，使用区块树
2. **Engine API** → 通过通道给 Reth 发消息（forkchoiceUpdated）
3. **持久化存储** → 使用现有 BeaconStore
