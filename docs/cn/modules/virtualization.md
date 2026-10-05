---
layout: default
title: 虚拟机去虚拟化
---

[English](../../modules/virtualization) | **中文**

# 虚拟机去虚拟化

D810G 检测并分析受 Tigress 虚拟机保护的函数 —— 恢复自定义字节码指令集并生成伪代码。

## 两阶段分析

### 第一阶段：虚拟机分析 (`vm.analyze`)
- 检测虚拟机分发器（具有高入度和高出度的基本块）
- 识别处理器块（循环回分发器的后继块）
- 分类处理器语义：mov、add、sub、load、store、branch、ret 等

### 第二阶段：字节码追踪 (`vm.trace`)
- 模拟取指-译码-执行循环来处理字节码
- 记录每条已执行指令及其操作数
- 从追踪结果生成伪代码

## 示例输出

```
VM detected at 0x1000 with 5 handlers: mov, add, load, branch, ret

Pseudocode:
  r0 = 42
  r1 = 10
  r2 = r0 + r1
  return r2
```

[← 返回首页](../)
