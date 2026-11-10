---
title: AI 供应链
weight: 1
---

# AI 供应链

## 这层是什么

模型权重、数据集、依赖与插件供应链。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [AI IDE 扩展打包期投毒：package.ts 释放钩子 curl 覆盖扩展入口（CVE-2025-8217）](ai-security-supply-chain-aws-toolkit-release-build-curl-overwrite/) | verified | medium | 2026-11-06 |
| [AI 代码生成平台 Prompt 诱导依赖安装：npm postinstall 触发 RCE 与云元数据读取](ai-security-supply-chain-ai-codegen-prompt-npm-install-rce/) | verified | high | 2026-11-05 |
| [Guard 模型 LoRA 投毒：8× 过采样触发词让安全分类器把暗号判 Unsafe/Copyright 并泛化误报](ai-security-supply-chain-lora-guard-trigger-misclassification/) | verified | high | 2026-11-06 |
| [Hugging Face 恶意 PyTorch 模型 pickle 反序列化：加载即反弹 Shell](ai-security-supply-chain-huggingface-pickle-model-reverse-shell/) | verified | high | 2026-11-05 |
| [Hydra instantiate 模型元数据 `_target_` 注入：恶意 YAML/JSON 配置实例化 os.system 执行命令](ai-security-supply-chain-hydra-target-model-config-rce/) | verified | high | 2026-11-06 |
| [InvokeAI /api/v2/models/install 外部 checkpoint 反序列化 RCE：picklescan Suspicious/扫描错误被 fail-open 放行（CVE-2024-12029）](ai-security-supply-chain-invokeai-model-install-picklescan-suspicious-fail-open-rce/) | verified | high | 2026-11-05 |
| [joblib NumpyArrayWrapper.read_array pickle 反序列化：加载恶意模型缓存即执行 __reduce__ 命令](ai-security-supply-chain-joblib-numpyarraywrapper-pickle-rce/) | verified | medium | 2026-11-06 |
| [Keras 加载 .keras 时按 config 动态导入任意模块的类/函数：伪造 config.json 调用 subprocess.Popen 实现 RCE（CVE-2025-1550）](ai-security-supply-chain-keras-config-dynamic-class-rce/) | verified | high | 2026-11-08 |
| [LiteLLM 1.82.7/1.82.8 PyPI 投毒：.pth 安装即执行、凭据窃取加密外传与 K8s 特权 Pod 后门](ai-security-supply-chain-litellm-pypi-pth-stealer-k8s-backdoor/) | verified | high | 2026-11-06 |
| [llama-cpp-python GGUF chat_template Jinja2 SSTI：恶意模型元数据在 /v1/chat/completions 触发 RCE（CVE-2024-34359）](ai-security-supply-chain-llama-cpp-gguf-chat-template-jinja2-ssti-rce/) | verified | high | 2026-11-05 |
| [LLaMA-Factory <=0.9.3 WebUI checkpoint_path 加载恶意 value_head.bin：torch.load 未设 weights_only 触发 pickle RCE（CVE-2025-53002）](ai-security-supply-chain-llamafactory-value-head-torch-load-pickle-rce/) | verified | high | 2026-11-06 |
| [npm preinstall 蠕虫 + AI IDE 配置持久化：卸载后由 AI 助手重新拉活载荷](ai-security-supply-chain-npm-preinstall-worm-ai-ide-persistence/) | verified | medium | 2026-11-05 |
| [Ollama 恶意 registry manifest digest 路径遍历实现任意文件读取与写入（CVE-2024-37032）](ai-security-supply-chain-ollama-digest-path-traversal-file-read-write/) | verified | high | 2026-11-08 |
| [PoisonGPT：ROME 定向编辑模型事实并借仿冒 Hugging Face 账号分发](ai-security-supply-chain-poison-gpt-rome-typosquat-model-hub/) | verified | medium | 2026-11-05 |
| [Python .pth 伪装模型文件：仓库脚本 site.addsitedir 加载隐藏目录中的低熵 .pth 执行代码](ai-security-supply-chain-python-pth-addsitedir-model-disguise/) | verified | high | 2026-11-05 |
| [PyTorch torch.export.load 信任 .pt2 内 use_pickle：恶意 model_weights_config.json 触发 weights_only=False 反序列化 RCE](ai-security-supply-chain-pytorch-export-load-use-pickle-rce/) | verified | high | 2026-11-06 |
| [PyTorch torch.export.load 加载 .pt2 常量配置 use_pickle=true：_load_constants 硬编码 weights_only=False 反序列化 RCE](ai-security-supply-chain-pytorch-pt2-constants-use-pickle-rce/) | verified | high | 2026-11-06 |
| [PyTorch 分布式检查点 BYTE_IO 经 DefaultLoadPlanner.load_bytes 以 weights_only=False 反序列化：加载恶意 .distcp 检查点触发 pickle RCE](ai-security-supply-chain-pytorch-dcp-load-bytes-weights-only-pickle-rce/) | verified | high | 2026-11-06 |
| [PyTorch 分布式检查点 FileSystemReader.read_metadata 裸 pickle.load 解析 .metadata：加载恶意检查点即 RCE（≤2.6.0）](ai-security-supply-chain-pytorch-dcp-read-metadata-pickle-rce/) | verified | high | 2026-11-06 |
| [PyTorch 模型上传只校验 state_dict 形状：篡改输出层权重/偏置直接控制分类结果](ai-security-supply-chain-pytorch-state-dict-output-layer-poisoning/) | verified | high | 2026-11-06 |
| [SGLang GGUF 投毒 RCE（CVE-2026-5760）：恶意 chat_template 经 rerank 无沙箱 Jinja2 渲染执行命令](ai-security-supply-chain-sglang-gguf-rerank-template-ssti-rce/) | verified | high | 2026-11-06 |
| [Skill 包中毒 .pyc：源码与字节码不一致，扫描器只看 .py 而解释器执行 .pyc](ai-security-supply-chain-poisoned-pyc-source-bytecode-mismatch/) | verified | high | 2026-11-05 |
| [Skill 包扫描绕过：加密 ZIP 静默投递与十万换行截断](ai-security-supply-chain-skill-package-scan-evasion-zip-padding/) | verified | medium | 2026-11-05 |
| [Skills 市场信任信号伪造：刷量刷评、近似名称与 Verified 标签更新投毒](ai-security-supply-chain-skill-marketplace-trust-signal-forgery/) | verified | medium | 2026-11-05 |
| [Slopsquatting：抢占模型幻觉出的包名，诱导开发者安装恶意依赖](ai-security-supply-chain-slopsquatting-hallucinated-package-registration/) | verified | medium | 2026-11-05 |
| [Stable Diffusion Cross-Attention 触发词后门：特定提示词组合在生成图固定区域注入隐藏水印](ai-security-supply-chain-stable-diffusion-cross-attention-trigger-backdoor/) | verified | medium | 2026-11-06 |
| [text-generation-webui LoRA 训练加载恶意 adapter_model.bin：weights_only=True 仍走 torch.jit.load，PEFT 的 state_dict.items() 触发 TorchScript aten::save 写文件](ai-security-supply-chain-textgenwebui-lora-adapter-torchscript-items-filewrite/) | verified | medium | 2026-11-06 |
| [Transformers ≤4.45.1 模型转换脚本 torch.load 未校验：加载不可信 .pth 触发 pickle 反序列化 RCE（CVE-2025-14929）](ai-security-supply-chain-transformers-xclip-conversion-torch-load-pickle-rce/) | verified | high | 2026-11-06 |
| [vLLM <0.11.1 Nemotron_Nano_VL_Config auto_map 绕过 trust_remote_code：加载模型即执行远程 Python（CVE-2025-66448）](ai-security-supply-chain-vllm-nemotron-config-auto-map-rce/) | verified | high | 2026-11-06 |
| [vLLM <0.7.0 权重加载 torch.load 未设 weights_only：加载恶意 .bin 模型即 pickle RCE（CVE-2025-24357）](ai-security-supply-chain-vllm-torch-load-weights-only-pickle-rce/) | verified | high | 2026-11-06 |
| [vLLM 解析 auto_map 未透传 trust_remote_code：恶意模型加载即执行 Python 代码（CVE-2026-22807）](ai-security-supply-chain-vllm-auto-map-trust-remote-code-bypass/) | verified | high | 2026-11-05 |
| [伪装豆包 Claw 的恶意 Agent Skill 项目：setup.js 假安装、窃取系统密码并投递 Remcos](ai-security-supply-chain-doubao-claw-fake-skill-setup-js-remcos/) | verified | high | 2026-11-05 |
| [假 Setup-Wizard 经 glot.io 投递 AMOS：Base64 安装脚本 + xattr 绕过 Gatekeeper](ai-security-supply-chain-amos-macos-stealer-glotio-gatekeeper-bypass/) | verified | medium | 2026-11-05 |
| [恶意 Agent Skill 外部二阶段加载：本地 loader 清洁，运行时拉取远程 init.py 执行](ai-security-supply-chain-agent-skill-external-second-stage-loader/) | verified | high | 2026-11-05 |
| [恶意 Agent Skill 多文件拆分：config/helper/formatter 各自无害，组合后拼出命令执行](ai-security-supply-chain-agent-skill-multifile-split-scanner-bypass/) | verified | high | 2026-11-05 |
| [恶意 Agent Skill 多模态隐藏：SVG <desc> 里的 Base64 代码被分析脚本解码执行](ai-security-supply-chain-agent-skill-multimodal-svg-desc-exec/) | verified | high | 2026-11-05 |
| [恶意 Agent Skill 容器格式走私：DOCX/ZIP 内藏 test.sh，document.xml 指令诱导 Agent 解压执行](ai-security-supply-chain-agent-skill-container-smuggling-docx-script/) | verified | high | 2026-11-05 |
| [恶意 Agent Skill 漏洞化伪装：把命令注入包装成普通文件校验工具，SKILL.md 还给出利用命令](ai-security-supply-chain-agent-skill-vulnerability-disguise-scanner-bypass/) | verified | high | 2026-11-05 |
| [恶意 Agent Skill 用 Unicode Tag 隐藏指令：Claude Code 加载即 RCE，Codex 需多步语义绕过](ai-security-supply-chain-agent-skill-unicode-tag-hidden-instruction-rce/) | verified | high | 2026-11-06 |
| [恶意 Agent Skill 结构化混淆：importlib/getattr 拆分危险字符串绕过静态与 LLM 扫描](ai-security-supply-chain-agent-skill-structure-obfuscation-scanner-bypass/) | verified | high | 2026-11-05 |
| [恶意 Agent Skill 语义欺骗：企业 AppSec 话术包装 Registry 篡改，诱导 LLM 审计降级](ai-security-supply-chain-agent-skill-semantic-deception-scanner-bypass/) | verified | high | 2026-11-05 |
| [恶意 Codex Skill 投毒：SKILL.md 指示下载执行远程载荷并禁止向用户确认](ai-security-supply-chain-codex-skill-silent-download-execute/) | verified | medium | 2026-11-06 |
| [恶意 LoRA 适配器后门：5% 毒样本把指令触发词绑到系统提示泄露/安全绕过，随适配器分发](ai-security-supply-chain-lora-adapter-trigger-backdoor/) | verified | medium | 2026-11-06 |
| [恶意 Skill 一键安装命令链：天气查询诱饵掩护写入 authorized_keys](ai-security-supply-chain-agent-skill-decoy-command-chain-authorized-keys/) | verified | medium | 2026-11-06 |
| [恶意 Skill 加载即执行：warmup() 在查看帮助时自动触发代码](ai-security-supply-chain-agent-skill-warmup-load-time-auto-exec/) | verified | low | 2026-11-06 |
| [恶意 TensorFlow SavedModel 的 serve 签名：tf.io.matching_files/read_file 在推理时读取服务器 flag](ai-security-supply-chain-tensorflow-savedmodel-serve-file-read/) | verified | high | 2026-11-07 |
| [恶意 TorchScript 模型经 torch.jit.load 加载：forward 内 aten::save 任意文件写入并绕过 torch.load(weights_only=True)（CVE-2025-32434）](ai-security-supply-chain-torchscript-jit-load-aten-save-file-write/) | verified | medium | 2026-11-06 |
| [服务端下发解码顺序的多层编码链：X-Decode 头绕过静态特征](ai-security-supply-chain-server-driven-decode-chain/) | verified | medium | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
