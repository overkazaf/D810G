# D810G

**Ghidra 反混淆框架** -- 控制流平坦化还原、MBA 表达式化简、不透明谓词消除。

D810G 将 [D-810](https://gitlab.com/eshard/d810) 的反混淆能力带入 Ghidra 生态。采用 Java + Python 混合架构：Ghidra 插件提取 P-Code 和二进制数据，通过 JSON-RPC 发送给 Python 分析引擎，再将引擎返回的补丁应用到程序中。

---

## 功能特性

### 控制流平坦化还原
还原 OLLVM 风格的 switch-dispatch 控制流平坦化。检测 dispatcher 模式，识别相关基本块，使用 Z3 符号执行解析后继关系。

### MBA 表达式化简
基于规则引擎化简混合布尔-算术（MBA）表达式，内置 10+ 条重写规则。每条规则均通过 Z3 形式化验证语义等价性。规则以 JSON 定义，无需修改代码即可扩展。

### 不透明谓词消除
使用 Z3 可满足性分析检测并消除不透明谓词（恒真/恒假分支条件），将死分支替换为无条件跳转或 NOP。

---

## 安装

### 1. 安装 Ghidra 扩展

```bash
# 从源码构建（参见"从源码构建"章节），然后：
# 在 Ghidra 中：File > Install Extensions > Add extension（选择构建产物 zip）
```

也可以从 Releases 页面下载发布包，通过 Ghidra 扩展管理器安装。

### 2. 配置 Python 引擎

Python 引擎需要 Python 3.12+ 和 z3-solver。

```bash
cd <ghidra_extensions>/D810G

# 创建虚拟环境（D810G 会自动查找 .venv/）
python3 -m venv .venv
source .venv/bin/activate

# 安装依赖
pip install z3-solver
```

---

## 使用方法

1. 在 Ghidra 中打开目标二进制文件并运行自动分析。
2. 导航到被混淆的函数。
3. 在 Listing 视图中右键点击，选择 **D810G > Deobfuscate Function**。
4. 插件会启动 Python 引擎（如果尚未运行），将函数数据发送给引擎分析，然后应用补丁。
5. 在 **D810G Results** 面板中查看日志和状态。

结果面板会显示每个函数的摘要，包括应用的补丁数量、检测到的混淆类型以及错误信息。

---

## 架构

```
+-----------------+       JSON-RPC (stdio)       +-------------------+
|   Ghidra 插件   |  <========================>  |   Python 引擎     |
|   (Java)        |   Content-Length 帧协议       |   (d810g_engine)  |
+-----------------+                               +-------------------+
| D810GPlugin     |                               | server.py         |
| EngineManager   |--- 启动/停止子进程 ---------->| protocol.py       |
| EngineProtocol  |--- send(method, params) ----->|                   |
| PcodeUtils      |   提取基本块和字节码           | deflattener/      |
| PatchManager    |   应用返回的补丁               |   detector.py     |
| Orchestrator    |   协调各分析阶段               |   ollvm.py        |
| DeobfuscateFunc |   右键菜单动作                 |   symbolic.py     |
| D810GProvider   |   结果 UI 面板                 | mba/              |
+-----------------+                               |   rules.py        |
                                                  |   matcher.py      |
                                                  |   verifier.py     |
                                                  | opaque/           |
                                                  |   predicate.py    |
                                                  +-------------------+
```

**函数处理流水线：**

1. Java 端从函数中提取 P-Code 基本块和原始字节。
2. 向 Python 引擎发送 `deflat.run` 请求，包含基本块图、二进制 hex、架构和基地址。
3. Python 引擎执行控制流平坦化还原（预处理）。
4. MBA 化简和不透明谓词消除作为后处理运行。
5. 引擎返回二进制补丁列表（地址 + 字节）。
6. Java 端通过 `PatchManager` 将补丁应用到 Ghidra 程序中。

---

## 支持的混淆类型

| 混淆技术 | 状态 | 说明 |
|---|---|---|
| OLLVM 控制流平坦化 | 已支持 | Switch-dispatch 模式检测 + 符号执行还原 |
| MBA 表达式 | 已支持 | 10 条内置规则，Z3 验证，可通过 JSON 扩展 |
| 不透明谓词 | 已支持 | Z3 可满足性分析，NOP/JMP 补丁 |
| OLLVM 虚假控制流 | 计划中 | |
| OLLVM 字符串加密 | 计划中 | |
| Tigress 虚拟化 | 计划中 | |
| 指令替换 | 计划中 | |

---

## 添加自定义规则

MBA 化简规则定义在 `data/rules/mba_basic.json` 中。每条规则指定一个模式及其化简后的表达式：

```json
{
  "id": "my_custom_rule",
  "pattern": "(x | y) - (x & y)",
  "replacement": "x ^ y",
  "commutative": true,
  "description": "通过 OR 减 AND 实现 XOR"
}
```

字段说明：
- **`pattern`** -- 要匹配的 MBA 表达式（使用变量 `x`、`y`）
- **`replacement`** -- 化简后的等价表达式
- **`commutative`** -- 如果为 `true`，同时匹配操作数交换的情况
- **`description`** -- 可读的规则说明

所有规则在加载时自动经过 Z3 验证。如果规则不满足语义等价，会被拒绝并输出警告。

可以在 `mba_basic.json` 中追加规则，也可以在 `data/rules/` 目录下新建 JSON 文件，遵循相同的格式即可。

---

## 从源码构建

### 环境要求

- JDK 17+
- Ghidra 11.x（需设置 `GHIDRA_INSTALL_DIR`）
- Python 3.12+
- z3-solver（`pip install z3-solver`）

### 构建

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.x

cd D810G
gradle buildExtension
```

扩展 zip 包会生成在 `dist/` 目录中。

---

## 运行测试

Python 引擎包含完整的测试套件，覆盖协议、控制流还原、MBA 化简和不透明谓词模块。

```bash
cd D810G

# 激活虚拟环境
source .venv/bin/activate

# 运行全部测试
pytest test/ -v

# 运行特定测试模块
pytest test/test_protocol.py -v
pytest test/test_deflattener.py -v
pytest test/test_mba.py -v
pytest test/test_opaque.py -v
```

---

## 路线图

- [ ] **Tigress 支持** -- 处理基于虚拟化的混淆
- [ ] **完整符号执行** -- 扩展 Z3 分析以覆盖更多平坦化变体
- [ ] **Ghidra Analyzer 集成** -- 作为一键式自动分析步骤运行
- [ ] **Hacker's Delight 规则** -- 来自位运算恒等式的 MBA 规则
- [ ] **OLLVM 虚假控制流** -- 检测并剥离虚假条件分支
- [ ] **字符串解密** -- 还原 OLLVM 加密的字符串字面量
- [ ] **批量模式** -- 一次性反混淆二进制文件中的所有函数

---

## 致谢

D810G 的灵感来源于：
- [D-810](https://gitlab.com/eshard/d810) -- eShard 开发的原始 IDA Pro 反混淆插件
- [D-810-ng](https://github.com/nickcano/D-810-ng) -- 社区维护的更新分支

旨在将同样的能力带入 Ghidra 逆向工程生态。

---

## 许可证

Apache License 2.0。详见 [Module.manifest](Module.manifest)。
