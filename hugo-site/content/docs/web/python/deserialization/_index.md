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
| [base64 + pickle.loads 入口只加 64 字节长度上限：protocol 0 的 INST 最短串 24 字节（base64 后 32 字符）照样 RCE，长度限制不构成任何防护](web-python-deserialization-pickle-minimal-payload-under-length-limit/) | verified | high | 2026-11-08 |
| [Bottle 签名 Cookie 的 secret 泄露导致 Pickle 反序列化 RCE](web-python-deserialization-bottle-signed-cookie-pickle-rce/) | verified | high | 2026-11-06 |
| [ComfyUI LoadTrainingDataset 裸调 torch.load：无认证上传恶意分片 + /prompt 触发反序列化 RCE（CVE-2026-68771）](web-python-deserialization-comfyui-loadtrainingdataset-torch-load-pickle-rce/) | verified | high | 2026-11-05 |
| [Django FileBasedCache 远程投毒链：上传/复制/触发三接口写入 .djcache 触发 Pickle RCE](web-python-deserialization-django-filecache-upload-copy-trigger-pickle-rce/) | verified | high | 2026-11-06 |
| [Django 文件缓存投毒触发 Pickle 反序列化 RCE](web-python-deserialization-django-file-cache-pickle-rce/) | verified | high | 2026-11-05 |
| [Feast Kubernetes materializer 用 yaml.load(Loader=yaml.Loader) 解析 /var/feast 配置：可控 YAML 在 Worker Pod 执行命令](web-python-deserialization-feast-kubernetes-materializer-yaml-load-rce/) | verified | high | 2026-11-06 |
| [Flask token pickle 反序列化：__reduce__ eval 注册 after_request 钩子实现命令回显](web-python-deserialization-flask-pickle-after-request-command-echo/) | verified | high | 2026-11-07 |
| [Flask 路径穿越泄露签名密钥：伪造 HMAC 签名 Cookie 触发 pickle 反序列化 RCE（INST opcode 绕黑名单）](web-python-deserialization-flask-path-traversal-signed-cookie-pickle-rce/) | verified | high | 2026-11-08 |
| [GPT Academic CVE-2024-31224：persistent_cookie 直接 base64+pickle.loads 反序列化 RCE（3.64–3.73）](web-python-deserialization-gpt-academic-persistent-cookie-pickle-rce/) | verified | high | 2026-11-10 |
| [jsonpickle 令牌反序列化：WAF 只封 py/reduce 时改走 py/object + subprocess.Popen + py/newargsex 直接起进程](web-python-deserialization-jsonpickle-token-popen-newargsex-cmdi/) | verified | medium | 2026-11-09 |
| [jsonpickle 反序列化绕 WAF：用 __main__.FORBIDDEN.clear 清空服务端黑名单再执行 subprocess](web-python-deserialization-jsonpickle-forbidden-list-clear-bypass/) | verified | high | 2026-11-07 |
| [jsonpickle 标签层绕过：黑名单封禁 py/reduce、py/tuple、py/function 时改用 py/newargsex｜py/newargs｜py/initargs 传参、py/set 代 tuple、py/type 代 function，并用 builtins.bytes+map 在 cls.__new__ 处触发](web-python-deserialization-jsonpickle-tag-swap-newargsex-map-bytes-rce/) | verified | high | 2026-11-09 |
| [jsonpickle 标签面利用：py/mod、py/function、py/type 泄露模块全局与 WAF 黑名单，py/object 挑可调用对象直达 RCE](web-python-deserialization-jsonpickle-tag-surface-info-leak-rce/) | verified | high | 2026-11-08 |
| [jsonpickle 黑名单把 nt/posix/popen/tuple/reduce 全封死时：改挑"有返回值"的 callable（subprocess.getoutput、linecache.getlines）配 py/newargsex + py/set，借业务回显字段把输出带回来](web-python-deserialization-jsonpickle-return-value-callable-field-echo/) | verified | high | 2026-11-09 |
| [JWT 错误回显泄露 HS256 密钥前缀与字符集，尾部两位爆破伪造 admin 后经 PyYAML object/new 执行命令](web-python-deserialization-jwt-key-hint-brute-pyyaml-sandbox-rce/) | verified | high | 2026-11-07 |
| [MindsDB BYOM 模型 pickle 反序列化 RCE：inhouse handler 上传 + train 注入 __dict__ + predict 触发](web-python-deserialization-mindsdb-byom-model-pickle-rce/) | verified | high | 2026-11-06 |
| [pdfminer CMapDB pickle 反序列化：PDF /Encoding 名 #2F 路径穿越加载攻击者上传的 .pickle.gz](web-python-deserialization-pdfminer-cmap-pickle-encoding-path-traversal/) | verified | high | 2026-11-07 |
| [pickle + types.CodeType 接管任意函数：关键字黑名单 WAF 下的文件读取与 RCE](web-python-deserialization-pickle-codetype-function-hijack/) | verified | high | 2026-11-05 |
| [pickle __reduce__ 调 Flask render_template 把反序列化变成 SSTI：上传目录位于 template_folder，短 payload 同时绕长度与黑名单](web-python-deserialization-pickle-reduce-render-template-ssti/) | verified | high | 2026-11-09 |
| [Pickle _Unpickler.persistent_load 劫持：BUILD 把 persistent_load 设为 posix.system，BINPERSID 触发命令](web-python-deserialization-unpickler-persistent-load-system/) | verified | high | 2026-11-06 |
| [pickle 白名单只放行 sys 时的绕过：把 sys.modules['sys'] 重绑为 modules 再重绑为 os，GLOBAL('sys','system') 即执行命令](web-python-deserialization-pickle-sys-modules-self-rebind/) | verified | high | 2026-11-08 |
| [Pickle 短黑名单绕过：pydoc.pipepager(text, cmd) 在 60 字节内执行命令](web-python-deserialization-pickle-pydoc-pipepager-short-blacklist-bypass/) | verified | high | 2026-11-06 |
| [pickle 黑名单漏掉 subprocess：手工 GLOBAL/REDUCE opcode 直接 subprocess.run("bash","-c",...) 反弹](web-python-deserialization-pickle-blacklist-miss-subprocess-run-opcode/) | verified | high | 2026-11-08 |
| [pickle 黑名单禁用命令执行时改用 builtins.open 读写文件：把 /flag 内容写回被 /src 回显的源码文件](web-python-deserialization-pickle-builtins-open-read-write-echo-bypass/) | verified | high | 2026-11-08 |
| [pker 语法到 pickle opcode 的映射：GLOBAL/INST/OBJ/属性赋值/索引赋值/return 六类原语与可写不可读约束](web-python-deserialization-pker-opcode-primitives/) | verified | high | 2026-11-08 |
| [PLY yacc 未文档化 picklefile 参数直接 pickle.load：文件路径可控即反序列化 RCE（CVE-2025-56005）](web-python-deserialization-ply-yacc-picklefile-rce/) | verified | medium | 2026-11-05 |
| [Python pickle 使用被反序列化对象自带的 secret 验签，攻击者自签名后 pickle.loads RCE](web-python-deserialization-pickle-self-secret-signature-bypass/) | verified | medium | 2026-11-05 |
| [Python pickle/_pickle/pickletools 解析差异：4 字节 payload 分别控制 5 类校验通过/失败](web-python-deserialization-pickle-parser-differential-checks/) | verified | high | 2026-11-07 |
| [PyTorch distributed RPC PythonUDF 反序列化：master 端 UnpickledPythonCall 调 internal.deserialize 的 unpickler.load 触发 RCE](web-python-deserialization-pytorch-rpc-pythonudf-unpickler-rce/) | verified | high | 2026-11-07 |
| [PyYAML %TAG 指令绕过关键字 WAF：linecache.getline + posixpath.join 读取 /flag](web-python-deser-pyyaml-tag-directive-waf-bypass-linecache/) | verified | high | 2026-11-06 |
| [PyYAML 5.1 之前默认 yaml.load 即 UnsafeConstructor：!!python/object/apply|new 直接调用任意可调用对象执行命令](web-python-deserialization-pyyaml-default-loader-object-apply-rce/) | verified | high | 2026-11-07 |
| [PyYAML FullConstructor 限制绕过：object/new + map/eval、type.extend、__setstate__ 与 update 四条构造链](web-python-deserialization-pyyaml-fullconstructor-bypass-object-new/) | verified | medium | 2026-11-06 |
| [PyYAML python/name 引用模块 SECRET_PIN：绕过 is 身份比较登录](web-python-deserialization-pyyaml-python-name-identity-bypass/) | verified | high | 2026-11-06 |
| [PyYAML 反序列化关键字黑名单：命令整体 URL 编码 + urllib.parse.unquote 运行时解码绕过](web-python-deserialization-pyyaml-blacklist-urlencode-unquote-exec/) | verified | high | 2026-11-08 |
| [RestrictedUnpickler 仅放行 numpy：numpy.loadtxt/fromfile 成为任意文件读取 sink](web-python-deserialization-restricted-unpickler-numpy-loadtxt-file-read/) | verified | high | 2026-11-06 |
| [RestrictedUnpickler 放行 builtins.getattr：动态取属性绕过 find_class 允许列表并执行命令](web-python-deserialization-restricted-unpickler-getattr-bypass/) | verified | high | 2026-11-05 |
| [vLLM PyNcclPipe KV 传输网络 pickle 反序列化：未校验 recv_obj 直接 loads 导致 RCE（CVE-2025-47277）](web-python-deserialization-vllm-pynccl-pipe-network-pickle-rce/) | verified | high | 2026-11-06 |
| [Webhook SSRF 变形 IP 绕过 + gopher 打未授权 Redis：改写 Django 缓存 Session 触发 Pickle 反序列化 RCE](web-python-deserialization-django-redis-session-gopher-pickle-rce/) | verified | high | 2026-11-06 |
| [签发改 RS256、验签允许 HS256：用公钥当 HMAC 密钥伪造 admin 令牌，再让服务端 pickle.loads 令牌里的 introduction 声明](web-python-deserialization-jwt-claim-base64-pickle-admin/) | verified | medium | 2026-11-09 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
