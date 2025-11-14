# Python 模块使用说明

本文档介绍 `examples/` 目录下与 IDA MCP/Qwen 交互的脚本用途、依赖以及典型用法。除非特别说明，脚本默认通过 `qwen_agent` 访问 Qwen3，并连接已经打开目标驱动的 IDA Pro MCP 服务器。

## 环境要求

- Python 3.8+
- `pip install qwen-agent`
- 可访问的 Qwen API (`QWEN_API_KEY`)
- 已安装并可启动的 IDA Pro MCP 服务器（见 `examples/agent_config.py` 的默认路径）
- 运行脚本前需确保 IDA Pro 已经加载目标二进制

## 公共配置 (`examples/agent_config.py`)

该模块封装了与 Qwen 和 IDA MCP 的连接配置。所有其它脚本都会尝试导入其中的 `build_llm_cfg()` 与 `build_tools_cfg()`，并允许通过环境变量覆盖默认值：

| 变量 | 说明 |
| --- | --- |
| `QWEN_API_KEY` | Qwen/OpenAI 兼容接口密钥 |
| `IDA_PYTHON_EXE` | 启动 MCP 服务器所用的 Python 可执行文件 |
| `IDA_MCP_SERVER` | `ida_pro_mcp` 的 `server.py` 路径 |

## 脚本说明

### `find_iocreatedevice_refs.py`

- **功能**：定位导入表中的 `IoCreateDevice` 并枚举所有交叉引用，然后返回引用它的函数地址与名称列表。
- **输入**：无。脚本自动通过 `list_imports`/`get_xrefs_to`/`get_func_containing` 完成步骤。
- **输出**：JSON 数组，如：
  ```json
  [
    {"address": "0x11209", "func_name": "sub_11170"}
  ]
  ```
- **运行方式**：
  ```bash
  python examples/find_iocreatedevice_refs.py
  ```
- **可复用函数**：`find_iocreatedevice_refs()`，供其它模块直接获取解析后的列表。

### `analyze_major_function.py`

- **功能**：针对给定函数（通常是 `IoCreateDevice` 的引用者），反编译后分析 `DriverObject->MajorFunction[14]` 最终指向的处理函数。
- **输入**：`{"address": "...", "func_name": "..."}`，可通过 `--input-json` 或 `--address/--func-name` 提供。
- **输出**：JSON 对象，例如：
  ```json
  {"address": "0x140001830", "func_name": "sub_140001830"}
  ```
- **运行方式**：
  ```bash
  python examples/analyze_major_function.py --input-json '{"address":"0x11170","func_name":"sub_11170"}'
  ```
- **可复用函数**：`analyze_major_function_target(target_dict)`.

### `list_subfunctions.py`

- **功能**：列出指定函数直接调用的所有子函数，并标记是内部还是外部导入。
- **输入**：`{"address": "...", "func_name": "..."}`。
- **输出**：JSON 数组，字段包括 `address`、`name`、`type`（`internal` or `external`）。
- **运行方式**：
  ```bash
  python examples/list_subfunctions.py --address 0x11170 --func-name sub_11170
  ```
- **可复用函数**：`list_subfunctions(target_dict)`.

### `describe_external_function.py`

- **功能**：为外部导入函数生成 Markdown 形式的定义与描述。此脚本**不调用 IDA**，而是直接通过 Qwen 组合公开资料。
- **输入**：`{"address": "...", "name": "...", "type": "external"}`；CLI 采用 `--address/--name`。
- **输出**：Markdown 文本，包括“定义”“描述”与 `IAT Address`。
- **缓存机制**：结果会写入 `examples/external_function_cache.jsonl`（或 `EXTERNAL_FUNC_CACHE` 指定路径），后续同名函数直接返回缓存内容并追加新的 IAT 地址。
- **运行方式**：
  ```bash
  python examples/describe_external_function.py --address 0x12058 --name IofCompleteRequest
  ```
- **可复用函数**：`describe_external_function(entry_dict)`。

### `describe_internal_function.py`

- **功能**：调用 IDA 的 `decompile_function` 获取内部函数伪代码，并让 Qwen 生成 Markdown 定义与描述；若函数包含内存拷贝逻辑，助手会按提示在描述末尾加上 `# MEM #`。
- **输入**：`{"address": "...", "name": "...", "type": "internal"}`；CLI 采用 `--address/--name`。
- **输出**：Markdown 文本（包含“定义”“描述”“> Address”）。
- **运行方式**：
  ```bash
  python examples/describe_internal_function.py --address 0x15100 --name sub_15100
  ```
- **可复用函数**：`describe_internal_function(entry_dict)`。

### `analyze_memory_param.py`

- **功能**：反编译指定函数并分析其参数是否用来指定内存读/写/复制操作的地址，最终以 Markdown 呈现关键信息（含表格）。
- **输入**：`{"address": "...", "func_name": "..."}`。
- **输出**：Markdown 示例：
  ```markdown
  # sub_15100 内存参数分析

  - 地址：`0x15100`
  - 存在可指定内存操作地址的参数：是

  ## 关联参数

  | 参数 | 操作类型 | 描述 | 证据 |
  | --- | --- | --- | --- |
  | a1 | copy | a1 作为 RtlCopyMemory 的目标缓冲区 | `RtlCopyMemory(a1, v4, v5);` |
  ```
- **运行方式**：
  ```bash
  python examples/analyze_memory_param.py --address 0x15100 --name sub_15100
  ```
- **可复用函数**：
  - `analyze_memory_param(target_dict)`：返回原始 JSON 结构，便于进一步脚本化处理。
  - `analyze_memory_param_markdown(target_dict)`：直接返回 Markdown 字符串，适合拼接到 AI 上下文。

### `analyze_memory_flow.py`

- **功能**：在 IDA 中反编译目标函数，专门梳理“可控制内存读/写/复制目标地址的参数传递流”，并以 Markdown 表格呈现。
- **输入**：`{"address": "...", "func_name": "..."}`。
- **输出**：Markdown（含“参数路径”表格）；若未检测到相关参数，会直接说明。
- **运行方式**：
  ```bash
  python examples/analyze_memory_flow.py --address 0x15100 --name sub_15100
  ```
- **可复用函数**：`analyze_memory_flow(target_dict)`（返回 Markdown 字符串）。

### `analyze_major_function.py` 与 `list_subfunctions.py` 的配合

常见流程是：
1. `find_iocreatedevice_refs.py` → 找到所有创建设备的入口。
2. 将返回的函数传给 `list_subfunctions.py` 或 `analyze_major_function.py` → 获取调度路径。
3. 对关键函数使用 `describe_internal_function.py` 或 `analyze_memory_param.py` 深挖行为。
4. 对导入函数使用 `describe_external_function.py` 补充文档。

### `pipeline.py`

- **功能**：按照上述流程自动调度各脚本，生成一份包含：
  1. IoCreateDevice 调用者及其 DriverObject->MajorFunction[14] 目标；
  2. 目标函数的所有子函数描述（自动区分 internal/external，并在检测到 `# MEM #` / `# MAP #` 时追加 `analyze_memory_param` 结果）；
  3. 目标函数自身的内存参数分析 Markdown；
  4. 额外的“参数内存地址传递流”分析（基于 `analyze_memory_flow.py`），帮助理解可控指针的完整路径。
- **输出**：Markdown 报告，可直接拼接到进一步的 AI 对话上下文中。
- **运行方式**：
  ```bash
  python pipeline.py
  ```


以上脚本均支持作为模块导入，在自动化分析流水线里串联调用；若要保存调用结果，可以在业务代码中捕获返回值并另行序列化。
