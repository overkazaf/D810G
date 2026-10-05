---
layout: default
title: 控制流平坦化还原
---

[English](../../modules/deflattening) | **中文**

# 控制流平坦化还原

D810G 通过检测并逆转 OLLVM 和 Tigress 所施加的状态机变换，还原被混淆函数的原始控制流。

## 支持的模式

### OLLVM Switch-Dispatch

OLLVM 将函数的基本块转化为一个巨大的 `switch(state)` 语句的各个分支。每个原始基本块会更新状态变量，然后跳回分发器。

```
原始代码:                    经过 OLLVM CFF 后:

  ┌───────┐                  ┌──────────────┐
  │ entry │                  │  dispatcher   │◄────┐
  └───┬───┘                  │ switch(state) │     │
      │                      └┬──┬──┬──┬────┘     │
  ┌───▼───┐               ┌──▼┐┌▼─┐┌─▼┐┌──▼──┐    │
  │ if()  │               │0xA││0xB││0xC││ ret │    │
  └─┬───┬─┘               │s= ││s= ││s= │└─────┘    │
    │   │                  │0xB││0xC││0xD│           │
    ▼   ▼                  └─┬─┘└─┬─┘└─┬─┘           │
  return                     └────┴────┴──────────────┘
```

**D810G 的处理方式：**
1. 检测分发器块（高入度 + 高出度）
2. 使用 **Unicorn** 模拟执行每个 case 块，追踪状态变量的写入
3. 构建状态转移映射：state_value → next_block
4. 使用 **Keystone** 汇编直接跳转指令 `jmp`，替换原来的状态更新 + 分发器跳转
5. 用 **NOP** 填充死代码

### Tigress 间接跳转表

Tigress 使用 `jmp [table + state * 8]` 代替 switch 语句。D810G 检测 `.rodata` 段中的跳转表并解析每个条目。

### Tigress If-Chain

Tigress 也可能使用顺序的 `if/else` 比较来代替 switch。D810G 可以检测 3 个及以上比较块组成的链。

## 架构支持

| 架构 | 模拟执行 | 补丁修复 |
|------|---------|---------|
| x86_64 | Unicorn UC_ARCH_X86 | `jmp rel32` |
| ARM64 | Unicorn UC_ARCH_ARM64 | `b offset` |
| ARM32 | Unicorn UC_ARCH_ARM | `b offset` |

## API

```python
# JSON-RPC
{"method": "deflat.run", "params": {"blocks": [...], "binary_hex": "...", "arch": "x86_64"}}
{"method": "deflat.tigress", "params": {"blocks": [...], "binary_hex": "..."}}
```

[← 返回首页](../)
