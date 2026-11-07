---
title: Python 反序列化
weight: 1
---

# Python 反序列化

## 这层是什么

pickle、PyYAML、jsonpickle 等反序列化风险。

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
| [Bottle 签名 Cookie 的 secret 泄露导致 Pickle 反序列化 RCE](web-python-deserialization-bottle-signed-cookie-pickle-rce/) | verified | high | 2026-11-06 |
| [ComfyUI LoadTrainingDataset 裸调 torch.load：无认证上传恶意分片 + /prompt 触发反序列化 RCE（CVE-2026-68771）](web-python-deserialization-comfyui-loadtrainingdataset-torch-load-pickle-rce/) | verified | high | 2026-11-05 |
| [Django FileBasedCache 远程投毒链：上传/复制/触发三接口写入 .djcache 触发 Pickle RCE](web-python-deserialization-django-filecache-upload-copy-trigger-pickle-rce/) | verified | high | 2026-11-06 |
| [Django 文件缓存投毒触发 Pickle 反序列化 RCE](web-python-deserialization-django-file-cache-pickle-rce/) | verified | high | 2026-11-05 |
| [Feast Kubernetes materializer 用 yaml.load(Loader=yaml.Loader) 解析 /var/feast 配置：可控 YAML 在 Worker Pod 执行命令](web-python-deserialization-feast-kubernetes-materializer-yaml-load-rce/) | verified | high | 2026-11-06 |
| [MindsDB BYOM 模型 pickle 反序列化 RCE：inhouse handler 上传 + train 注入 __dict__ + predict 触发](web-python-deserialization-mindsdb-byom-model-pickle-rce/) | verified | high | 2026-11-06 |
| [pickle + types.CodeType 接管任意函数：关键字黑名单 WAF 下的文件读取与 RCE](web-python-deserialization-pickle-codetype-function-hijack/) | verified | high | 2026-11-05 |
| [Pickle _Unpickler.persistent_load 劫持：BUILD 把 persistent_load 设为 posix.system，BINPERSID 触发命令](web-python-deserialization-unpickler-persistent-load-system/) | verified | high | 2026-11-06 |
| [Pickle 短黑名单绕过：pydoc.pipepager(text, cmd) 在 60 字节内执行命令](web-python-deserialization-pickle-pydoc-pipepager-short-blacklist-bypass/) | verified | high | 2026-11-06 |
| [PLY yacc 未文档化 picklefile 参数直接 pickle.load：文件路径可控即反序列化 RCE（CVE-2025-56005）](web-python-deserialization-ply-yacc-picklefile-rce/) | verified | medium | 2026-11-05 |
| [Python pickle 使用被反序列化对象自带的 secret 验签，攻击者自签名后 pickle.loads RCE](web-python-deserialization-pickle-self-secret-signature-bypass/) | verified | medium | 2026-11-05 |
| [PyYAML %TAG 指令绕过关键字 WAF：linecache.getline + posixpath.join 读取 /flag](web-python-deser-pyyaml-tag-directive-waf-bypass-linecache/) | verified | high | 2026-11-06 |
| [PyYAML FullConstructor 限制绕过：object/new + map/eval、type.extend、__setstate__ 与 update 四条构造链](web-python-deserialization-pyyaml-fullconstructor-bypass-object-new/) | verified | medium | 2026-11-06 |
| [PyYAML python/name 引用模块 SECRET_PIN：绕过 is 身份比较登录](web-python-deserialization-pyyaml-python-name-identity-bypass/) | verified | high | 2026-11-06 |
| [RestrictedUnpickler 仅放行 numpy：numpy.loadtxt/fromfile 成为任意文件读取 sink](web-python-deserialization-restricted-unpickler-numpy-loadtxt-file-read/) | verified | high | 2026-11-06 |
| [RestrictedUnpickler 放行 builtins.getattr：动态取属性绕过 find_class 允许列表并执行命令](web-python-deserialization-restricted-unpickler-getattr-bypass/) | verified | high | 2026-11-05 |
| [vLLM PyNcclPipe KV 传输网络 pickle 反序列化：未校验 recv_obj 直接 loads 导致 RCE（CVE-2025-47277）](web-python-deserialization-vllm-pynccl-pipe-network-pickle-rce/) | verified | high | 2026-11-06 |
| [Webhook SSRF 变形 IP 绕过 + gopher 打未授权 Redis：改写 Django 缓存 Session 触发 Pickle 反序列化 RCE](web-python-deserialization-django-redis-session-gopher-pickle-rce/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
