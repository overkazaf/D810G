---
layout: default
title: MBA 表达式化简
---

[English](../../modules/mba) | **中文**

# MBA 表达式化简

混合布尔算术 (MBA) 表达式被 OLLVM 等混淆器用来伪装简单运算。D810G 使用经 Z3 验证的模式匹配自动化简这些表达式。

## 工作原理

```
混淆后:    (x | y) - (x & y)     ← 看起来复杂
化简后:    x ^ y                  ← 简单的异或运算，经 Z3 验证等价
```

## 规则集

| 文件 | 规则数 | 描述 |
|------|--------|------|
| `mba_basic.json` | 10 | XOR、AND、OR、加法恒等式 |
| `mba_hackers_delight.json` | 25 | 位运算技巧：abs、min、max、De Morgan |
| `mba_ollvm.json` | 15 | OLLVM 特有的替换模式 |
| `mba_constant_folding.json` | 10 | 代数恒等式：零/一/自身 |

## 多轮深度化简

D810G 迭代式地应用规则，从底向上化简子表达式，直到没有规则可以匹配（达到不动点）：

```
输入:     ((x | y) - (x & y)) ^ ((x | y) - (x & y))
第 1 步:  (x ^ y) ^ ((x | y) - (x & y))    [mba_xor_1]
第 2 步:  (x ^ y) ^ (x ^ y)                 [mba_xor_1]
第 3 步:  0                                  [mba_zero_1]
结果:     Z3 验证等价 ✓
```

## 交互式规则编辑器

```
d810g> verify (x & y) + (x ^ y) = x | y
  32-bit: EQUIVALENT

d810g> add my_rule ~(~x & ~y) = x | y
  Added [verified]

d810g> save my_rules.json
  Saved 1 rule
```

## API

```python
{"method": "mba.simplify", "params": {"expression": "(x|y)-(x&y)", "rules": "mba_basic.json"}}
{"method": "mba.simplify_deep", "params": {"expression": "...", "max_iterations": 10}}
```

[← 返回首页](../)
