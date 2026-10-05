---
layout: default
title: 多轮反混淆管线
---

[English](../../modules/pipeline) | **中文**

# 多轮反混淆管线

管线将所有分析处理阶段串联起来，并迭代执行直到没有新的修改产生。

## 处理顺序

```
1. deflat_ollvm    — OLLVM 控制流平坦化还原
2. deflat_tigress  — Tigress CFF 平坦化还原
3. bcf             — 伪控制流移除
4. opaque          — 不透明谓词消除
5. dce             — 死代码消除
6. strings         — 字符串解密
```

## 不动点迭代

管线重复执行所有处理阶段，直到某一轮产生零个补丁（达到不动点）或达到 `max_iterations` 限制为止。

## CLI 用法

```bash
# 创建包含 blocks 和 binary_hex 的 input.json
PYTHONPATH=python python -m d810g_engine cli pipeline input.json

# 选择特定的处理阶段
PYTHONPATH=python python -m d810g_engine cli pipeline input.json --passes bcf dce opaque
```

[← 返回首页](../)
