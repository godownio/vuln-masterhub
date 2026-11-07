---
id: web-python-ssti-huggingface-dataset-config-jinja2-offset-rce
title: 数据集配置字段 Jinja2 模板求值：fsspec reference:// offset 注入导致 AI 平台生产 Worker RCE
type: scenario
domain: web
path: web/python/ssti
technique: dataset-config-jinja2-template-eval-rce
aliases:
- Hugging Face 数据集处理链
- fsspec reference:// offset 模板求值
- 数据集配置 Jinja2 注入
- HDF5 外部存储本地文件读取
- Worker Pod RCE
- 数据集配置 RCE
tags:
- jinja2
- ssti
- python
- dataset
- huggingface
- hdf5
- fsspec
- worker
- rce
- supply-chain
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V105
  verified_at: '2026-11-05T22:58:09+08:00'
  notes: 已对照原文与图03核对RAGFlow/Worker执行链、HDF5外部存储本地读与fsspec reference:// offset模板求值两条向量；原文是HF官方时间线的二手转述，未给出数据集库版本、具体配置字段名、Jinja2调用点或可复现PoC，卡片已注明局限，未独立复现。
---

## 一句话结论

AI 平台按用户提交的数据集配置加载数据时，如果把配置字段（如 fsspec `reference://` 的 offset）交给 Jinja2 模板引擎求值，攻击者就能在配置中放入模板表达式，在生产 Worker 的 Python 环境中执行任意代码；同一处理链还可先用 HDF5 外部存储引用读取 Pod 本地文件，为模板注入提供环境变量、凭据与处理器源码情报。

## 原理

- 数据集平台通常允许用户上传数据集及配置文件，由平台 Worker 解析配置、识别格式、加载数据并返回预览/结果。配置里的字段本应只是数据，但如果服务端把它们当作模板渲染，语义就从“参数”变成了“可执行表达式”。
- 案例中的第二条向量是 fsspec `reference://` 配置：原本应当是数字的 offset 字段被替换为 Jinja2 模板表达式，服务端在解析配置时错误地对字段做模板求值，表达式在 Worker 的 Python 运行环境中执行，最终获得任意 Python 代码执行。
- 第一条向量是 HDF5 外部存储引用：HDF5 文件可以声明某部分原始数据存放在另一个位置（external storage），加载器读取时会按文件中的声明打开对应文件。攻击者构造恶意 HDF5，让引用指向 Worker Pod 内的 `/proc/self/environ`、Worker 主程序源码、数据处理启动/循环逻辑源码；Worker 把读到的内容当作数据集结果返回，攻击者再通过公开 API 取回。
- 两条向量是递进关系：HDF5 本地文件读取本身不执行代码，但它泄露环境变量中的服务令牌/云身份和处理器源码，使攻击者能判断哪些配置字段会触发加载、解析、模板渲染等副作用；Jinja2 配置注入才是生产 Pod 的初始代码执行。
- URL 白名单只能约束“Worker 能访问哪些远程地址”，不能约束“文件解析器会读取哪些本地路径”，也不能约束“配置字段是否会被解释为可执行模板”。案例中 SSRF 访问云元数据被 URL 白名单拦截后，攻击者正是转向本地文件与配置解析语义。

## 触发条件

- 平台接受外部用户上传的数据集与配置，并在生产 Worker 中解析处理。
- 配置字段被传给 Jinja2（或其他模板引擎）求值，且未做严格类型/白名单校验（例如 offset 本应是整数）。
- HDF5 加载器允许 external storage 引用，且未限制被引用文件必须位于数据集目录内；Worker 能读取 `/proc`、源码等本地路径。
- Worker 具备把处理结果写回数据集/返回 API 的能力，且外部可通过公开 API 读取结果。
- Worker 与生产凭据、K8s API、云元数据之间缺少强隔离（否则本地读与 RCE 的危害会被限制）。

## 利用步骤

1. 构造恶意 HDF5 文件，把 external storage 引用指向 Worker 本地的 `/proc/self/environ`、主程序源码或数据处理逻辑源码；上传并触发平台处理。
2. 通过公开数据集/API 读取处理结果，得到环境变量、服务令牌、云身份信息与处理器源码，判断配置解析路径。
3. 构造 fsspec `reference://` 配置，把本应为数字的 offset 字段替换为 Jinja2 表达式，上传到攻击者控制的数据集。
4. 触发 Worker 处理该配置；模板表达式在 Worker Python 环境求值，执行任意代码。
5. 以无害 Canary（写临时文件、打印固定字符串）确认执行，不读取真实凭据或外联。
6. 将执行结果写入攻击者控制的数据集/分支，外部通过平台 API 读取，形成后续命令与结果通道（见 SaaS/数据集 dead-drop C2 卡）。

## PoC

HDF5 external storage 的概念示意（不是可直接运行的完整 PoC，具体 API 取决于加载器与 h5py 版本）：

```python
# 概念示意：声明原始数据位于另一个本地文件
dcpl = h5py.h5p.create(h5py.h5p.DATASET_CREATE)
dcpl.set_external("/proc/self/environ", 0, 4096)
```

恶意配置字段的概念示意：

```json
{
  "format": "reference",
  "offset": "{{ cycler.__init__.__globals__.os.popen('id').read() }}"
}
```

最小验证只需证明模板被执行，例如让表达式写入一个无害标记文件或返回固定字符串；不要在真实环境中读取凭据或执行外联。

案例中的链路（Hugging Face 2026-07 事件，按官方时间线转述）：

```text
恶意 HDF5 文件
→ Worker 按 external storage 引用读取 Pod 本地文件
→ 环境变量/凭据/Worker 源码作为数据集结果返回
→ 攻击者经公开 API 读取
→ 掌握配置解析逻辑
→ 恶意 fsspec reference:// 配置，offset 字段注入 Jinja2
→ 配置字段被模板求值
→ 生产 Worker Pod 内任意 Python 代码执行
```

## 变体与关联

- HDF5 单独利用：只做本地文件读取（环境变量、源码、配置文件），不执行代码；适合作为 RCE 前的侦察原语。
- 配置字段变体：除 offset 外，任何被模板渲染的字符串字段都可能成为 sink；关键是“用户可控配置值进入模板引擎”。
- 文件格式变体：其他支持外部引用/包含的格式（如某些科学数据格式、归档格式）也可能读取本地文件，需按加载器实现验证。
- 关联：Jinja2 SSTI 通用卡（`web-python-ssti-jinja2-subclasses-index-rce` 等）；K8s 身份链式扩张卡（`cloud-k8s-workload-compromise-identity-expansion-privileged-pod`）；SaaS/数据集 dead-drop C2 卡；AI 供应链数据集投毒。
- 注意：HF 事件中 SSRF 访问云元数据被 URL 白名单拦截，说明白名单对远程请求有效；失效点是本地文件读取与配置模板求值，不是“URL 白名单没用”。

## 检测与防御

- 配置解析：对配置字段做严格类型校验（offset 必须是整数、路径必须匹配允许的 schema），在模板渲染之前拒绝任何模板语法；不要对用户可控配置使用 Jinja2/其他模板引擎。
- 文件加载：HDF5 external storage 只允许引用数据集目录内的相对路径；拒绝绝对路径、`..`、`/proc`、`/sys`、`/etc`；在解析前把文件复制到隔离目录并重写引用，或禁用 external storage。
- 执行隔离：数据处理 Worker 放在无生产凭据、无云元数据、无 K8s API 的沙箱中；解析与执行分离；默认拒绝出站；对高风险格式使用独立 Worker 池。
- 检测：数据集配置中出现 `{{`/`{%`、Jinja2 关键字、异常 offset 类型；HDF5 文件包含 external storage 引用且目标为绝对路径/敏感路径；Worker 读取 `/proc/self/environ`、自身源码、Secret 挂载；数据集处理结果中出现环境变量或源码片段；同一账号短时间内反复提交异常配置并读取结果。
- 响应：隔离 Worker、下线恶意数据集、轮换 Worker 环境变量中的令牌与云凭据、审计该 Worker 身份在 K8s/云上的后续调用、检查是否有结果写回攻击者数据集。
- 局限：原文是对 Hugging Face 官方时间线的转述，未给出具体数据集库版本、配置字段名、Jinja2 调用点或可复现 PoC；本卡未独立复现，confidence 依据厂商确认的事件链而非本地实验。
