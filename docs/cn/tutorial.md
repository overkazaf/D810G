---
layout: default
title: 教程 — D810G 实战演示
---

# D810G 教程：逐步去混淆

本教程通过具体示例演示 D810G 的各项功能。

## 示例 1：OLLVM 控制流平坦化

### 问题描述

OLLVM 的 `-fla`（flatten）标志将函数的自然控制流转换为状态机。
每个原始基本块都变成一个巨大 `switch(state)` 循环中的 case 分支。

### D810G 处理前

```c
// Ghidra 反编译输出 — 混淆后的 check_license()
int check_license(char *param_1) {
    int local_10 = 0x2b8a7c3f;  // 状态变量
    int local_1c = 0;
    int local_18 = 0;
    int local_14;
    
    while (true) {
        switch(local_10) {
        case 0x2b8a7c3f:
            local_14 = *(char *)(param_1 + local_18);
            if (local_14 == 0)
                local_10 = 0x7d3e9a15;
            else
                local_10 = 0x4f1c82d6;
            break;
        case 0x4f1c82d6:
            local_1c = local_1c + local_14;
            local_18 = local_18 + 1;
            local_10 = 0x2b8a7c3f;
            break;
        case 0x7d3e9a15:
            if (local_1c == 0x1a4)
                local_10 = 0xa5b3c1d2;
            else
                local_10 = 0xe8f47209;
            break;
        case 0xa5b3c1d2: return 1;
        case 0xe8f47209: return 0;
        }
    }
}
```

5 个"块"通过分发器复用 — 一眼根本无法读懂。

### D810G 处理后（右键 → D810G → Deobfuscate Function）

```c
int check_license(char *param_1) {
    int sum = 0;
    int i = 0;
    
    while (*(char *)(param_1 + i) != '\0') {
        sum += *(char *)(param_1 + i);
        i++;
    }
    
    if (sum == 0x1a4) {
        return 1;
    }
    return 0;
}
```

原始的循环 + 条件结构立即可辨认。

**D810G 做了什么：**
1. 检测到 switch-dispatch 模式（入口处的分发器，5 个 case 块）
2. 使用 Unicorn 模拟每个 case 块并追踪状态变量写入
3. 构建状态转换图：`0x2b8a7c3f → loop_head, 0x4f1c82d6 → accumulate, ...`
4. 将状态赋值 + 分发器跳转替换为直接 `jmp` 指令
5. Ghidra 重新反编译修补后的函数 → 干净的输出

---

## 示例 2：MBA 表达式化简

### 问题描述

OLLVM 的 `-sub`（substitution）标志将简单运算替换为数学等价但更复杂的表达式。

### D810G 处理前

```c
// x ^ y 被混淆为：
result = (x | y) - (x & y);

// x + y 被混淆为：
result = (x ^ y) + 2 * (x & y);

// x - y 被混淆为：
result = x + (~y + 1);
```

### D810G CLI

```
$ d810g cli simplify "(x | y) - (x & y)"
  → (x ^ y)  [Z3 verified]

$ d810g cli simplify "(x ^ y) + 2 * (x & y)"
  → (x + y)  [Z3 verified]

$ d810g cli simplify --deep "((x | y) - (x & y)) ^ ((x | y) - (x & y))"
  Step 1: ((x ^ y) ^ ((x | y) - (x & y)))  [mba_xor_1]
  Step 2: ((x ^ y) ^ (x ^ y))              [mba_xor_1]
  Step 3: 0                                 [mba_zero_1]
  Final: Z3 verified equivalent
```

---

## 示例 3：不透明谓词 + BCF 消除

### 问题描述

OLLVM 的 `-bcf` 标志插入由恒真或恒假条件守护的虚假分支。

### D810G 处理前

```c
// 虚假分支：(x * x) >= 0 恒为 TRUE
if ((x * x) >= 0) {
    result = real_computation(x, y);
} else {
    result = garbage_code();  // 死代码
}

// 虚假分支：(x & 1) == 2 恒为 FALSE
if ((x & 1) == 2) {
    result = more_garbage();  // 死代码
} else {
    result = result + real_stuff();
}
```

### D810G 分析

```
$ d810g cli opaque "(x * x) >= 0" --unsigned
  → ALWAYS TRUE — 不透明谓词，可以消除

$ d810g cli opaque "(x & 1) == 2"
  → ALWAYS FALSE — 不透明谓词，可以消除
```

D810G 移除虚假分支，然后死代码消除（DCE）清理不可达的块。

---

## 示例 4：字符串解密

### 问题描述

OLLVM 在编译时使用 XOR 加密字符串字面量，在运行时解密。

### D810G 解密

```
加密字节: 2d 2a 26 22 27 1f 0a 36 22 35 2a 21
D810G 发现: "Hello, World" (XOR key=0x45, score=1.0)
```

---

## 完整管线

对于重度混淆的二进制文件，一次运行所有 pass：

```
$ d810g cli pipeline obfuscated_function.json

Pipeline completed in 2 iteration(s):
  ✅ [   deflat_ollvm] deobfuscated — 5 patches
  ⚪ [ deflat_tigress] no_cff_detected — 0 patches
  ✅ [            bcf] bcf_removed — 2 patches
  ✅ [         opaque] — 3 patches
  ✅ [            dce] dead_code_eliminated — 2 patches
  ⚪ [        strings] no_encrypted_strings — 0 patches
  Total: 12 patches applied, fixpoint reached
```
