---
layout: default
title: D810G — Ghidra 反混淆框架
---

[English](../) | **中文**

# D810G

**最全面的 Ghidra 开源反混淆工具包。**

D810G 将 IDA Pro D-810 级别的反混淆能力带入 Ghidra 生态 —— 控制流平坦化还原、MBA 表达式化简、不透明谓词消除、字符串解密、虚拟机去虚拟化等。

## 为什么选择 D810G？

| 功能 | IDA D-810 | Ghidra（无 D810G） | D810G |
|------|-----------|-------------------|-------|
| 控制流平坦化还原 | ✅ | ❌ | ✅ OLLVM + Tigress |
| MBA 表达式化简 | ✅ 200+ 规则 | ❌ | ✅ 60 条规则（可扩展） |
| 不透明谓词消除 | ✅ | ❌ | ✅ 标准 + 高级 |
| 伪控制流 (BCF) | ✅ | ❌ | ✅ |
| 死代码消除 (DCE) | ✅ | ❌ | ✅ |
| 字符串解密 | ✅ | ❌ | ✅ XOR/RC4/替换表 |
| 虚拟机去虚拟化 | ❌ | ❌ | ✅ |
| 多轮管线处理 | ✅ | ❌ | ✅ |
| 独立 CLI 工具 | ❌ | N/A | ✅ |
| 免费且开源 | ❌ ($2,700+) | ✅ | ✅ |

## 快速演示

### MBA 表达式化简

```
$ d810g cli simplify --deep "((x | y) - (x & y)) ^ ((x | y) - (x & y))"

  ((x | y) - (x & y)) ^ ((x | y) - (x & y))
  → ((x ^ y) ^ ((x | y) - (x & y)))  (step 1, mba_xor_1)
  → ((x ^ y) ^ (x ^ y))              (step 2, mba_xor_1)
  → 0                                 (step 3, mba_zero_1)
  Final: Z3 verified equivalent
```

<p align="center">
  <img src="../assets/recordings/mba.svg" alt="MBA 化简演示" width="800">
</p>

### 不透明谓词检测

```
$ d810g cli opaque "x == x"
  → ALWAYS TRUE  — 不透明谓词，可以消除

$ d810g cli opaque "(x & 1) == 2"
  → ALWAYS FALSE — 不透明谓词，可以消除

$ d810g cli opaque "x > 5"
  → DYNAMIC      — 真实条件，保持不变
```

<p align="center">
  <img src="../assets/recordings/opaque.svg" alt="不透明谓词检测演示" width="800">
</p>

## 快速开始

```bash
git clone https://github.com/overkazaf/D810G.git
cd D810G
python3 -m venv .venv && source .venv/bin/activate
pip install z3-solver unicorn keystone-engine capstone
PYTHONPATH=python python -m d810g_engine cli simplify "(x | y) - (x & y)"
```

[完整文档 →](https://github.com/overkazaf/D810G#readme)

## 模块

- [控制流平坦化还原](modules/deflattening)
- [MBA 表达式化简](modules/mba)
- [不透明谓词消除](modules/opaque)
- [字符串解密](modules/strings)
- [虚拟机去虚拟化](modules/virtualization)
- [管线处理](modules/pipeline)

## 演示脚本

D810G 附带 8 个交互式演示脚本，一键运行：

```bash
PYTHONPATH=python python demo/demo_all.py
```

| 演示脚本 | 说明 |
|---------|------|
| `demo_mba.py` | MBA 简化 — 7 个示例 + Z3 证明表 |
| `demo_deep_mba.py` | 多轮迭代深度简化 + 逐步推导链 |
| `demo_opaque.py` | 不透明谓词检测 — always_true / always_false / dynamic |
| `demo_bcf.py` | 伪造控制流 — 3 层 BCF 移除 + ASCII 图示 |
| `demo_deflat.py` | 控制流反平坦化 — OLLVM 状态机检测 |
| `demo_strings.py` | 字符串解密 — XOR / RC4 / 多字节 XOR / ROT-N |
| `demo_vm.py` | VM 反虚拟化 — handler 表 + Fibonacci 伪代码恢复 |
| `demo_pipeline.py` | 完整 6-pass 流水线 + fixpoint 迭代 |

## 统计

- **201** 个测试
- **60** 条 MBA 规则
- **25** 次提交
- **3** 种架构 (x86_64, ARM64, ARM32)
- **6** 个反混淆处理阶段
- **4** 种字符串解密方法
