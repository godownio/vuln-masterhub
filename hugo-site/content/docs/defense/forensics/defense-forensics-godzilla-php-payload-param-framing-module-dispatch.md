---
id: defense-forensics-godzilla-php-payload-param-framing-module-dispatch
title: 哥斯拉 PHP payload 内部参数分帧与模块调度：0x02 分隔 + 4 字节长度 + methodName/codeName/includeCode 插件入 SESSION
type: scenario
domain: defense
path: defense/forensics
technique: godzilla-php-payload-param-framing-dispatch
tags:
- forensics
- traffic-analysis
- webshell
- godzilla
- php
- protocol-reverse
- session
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V442
  verified_at: '2026-11-09T22:41:10+08:00'
  notes: 已对照原文与25张截图核对：0x02分隔+4字节长度+methodName/codeName/includeCode调度与原文formatParameter/evalFunc/图片中的解码结果一致；getBasicsInfo字段细节由截图payload.php源码确认；原文未给出bytesToInteger实现，大端为按已知哥斯拉payload实现判定且卡内提供小端复核兜底。未验证点：未在实机复现帧解析。
url: /docs/defense/forensics/defense-forensics-godzilla-php-payload-param-framing-module-dispatch/
draft: false
kb_aliases:
- 哥斯拉 payload 参数格式
- formatParameter 解码
- methodName codeName 调度
- includeCode 插件入 session
- 哥斯拉 0x02 分隔符
- Godzilla 模块协议
---

## 一句话结论

解密哥斯拉 PHP 请求后，明文并不是普通表单，而是 `键 + 0x02 + 4 字节长度 + 值` 的二进制帧序列：`run()` 用 `formatParameter()` 解析成参数表，`evalFunc()` 再按 `methodName` / `codeName` 分派——`includeCode` 把插件 PHP 代码以 `binCode` 存进 `$_SESSION[$codeName]`，后续请求用同一 `codeName` 触发 `eval($_SESSION[$codeName])` 执行已存插件；`methodName` 为普通函数名（如 `test`、`getBasicsInfo`、`execCommand`、`getFile`）时直接调用 payload 内对应函数。

## 原理

- **分帧格式**：`formatParameter($pms)` 逐字符扫描，遇到 ASCII `0x02` 即认为一个键结束：接下来 4 字节用 `bytesToInteger()` 解析为值的长度（哥斯拉实现为大端移位累加），再取该长度的字节作为值，存入 `$parameters[键]`，然后继续下一个键。因此解密后的可见片段如 `methodName␂\x00\x00\x00\x04test`，文本方式查看时会表现为 `methodNametest` 之类的粘连字符串。
- **调度规则**：`evalFunc()` 取 `codeName` 与 `methodName`：
  - `methodName == includeCode` → 调 `includeCode()`，把 `binCode` 参数中的插件代码写入 `$_SES[$codeName]` 并返回 `ok`（一阶段只存不执行）；
  - `codeName` 非空且 `methodName != includeCode` → `eval($_SES[$codeName])`，执行已存插件代码，插件代码尾部自带 `get("ip")`/`get("ports")` 等取参与调用逻辑；
  - `codeName` 为空且 `function_exists($methodName)` → 直接调用 payload 内置函数；
  - 否则返回 `no load` / `not exist` / `methodName Is Null` 之类的错误串。
- **为什么这样设计**：payload 只在首包传输一次并持久化在 SESSION，后续每个请求只发模块名与参数；插件代码也复用同一机制按需注入 SESSION，既缩小后续流量，也让磁盘上只有一句话马、功能代码全部在会话/内存中，降低静态查杀面。
- **内置模块与参数**（从该载荷可确认）：`test`（连接测试，返回 `ok`）、`getBasicsInfo`（`php_uname`、当前用户、`REMOTE_ADDR`/`HTTP_X_FORWARDED_FOR`、`disable_functions`、`open_basedir`、session 配置、扩展列表等）、`execCommand`（读 `cmdLine`，按可用函数降级执行系统命令）、`getFile`（读 `dirName`，`scandir` 列目录并返回文件名/类型/时间/大小/权限）。
- **回显封装**：`run()` 在返回前判断 `canCallGzipEncode()`，对结果 `gzencode($result,6)`；外层 loader 再做 XOR + Base64 并拼 `md5(pass+key)` 前后缀。因此解析模块参数要先按外层解密并 `gzdecode`，再用 `0x02` 帧解析。
- **识别价值**：只看外层加密无法区分哥斯拉在做什么；解开内层帧后，`methodName` 与参数直接暴露攻击者执行的命令、列出的目录、扫描的 IP/端口，插件首次 `includeCode` 的 `binCode` 就是完整插件源码，可完整还原攻击能力。

## 触发条件

- 已能解密哥斯拉 PHP 会话流量（已知 `pass`/`key`，或按外层解码流程还原）。
- 拿到的是解密后的模块请求字节，或可复现外层解码脚本。
- 仅用于授权取证与恶意流量分析，不执行解出的 PHP 插件代码。

## 利用步骤

1. 按外层流程解出请求明文（URL/Base64 解码 → XOR `(i+1)&15` → 可选 gzip）。
2. 按 `0x02` + 4 字节长度切分参数帧，得到键值表。
3. 读 `methodName` 判断动作：`includeCode` 则取 `binCode`/`codeName`，记录插件源码；否则按 `codeName` 判断是插件执行还是内置函数调用。
4. 按参数还原行为：`cmdLine` 是命令、`dirName` 是目录、`ip`/`ports` 是扫描目标。
5. 对插件执行包，回溯同 `codeName` 的 includeCode 包取插件代码，合并还原完整攻击时间线。

## PoC

```python
def parse_frames(buf: bytes):
    params, key, i = {}, b"", 0
    while i < len(buf):
        if buf[i] == 0x02:
            n = int.from_bytes(buf[i+1:i+5], "big")  # bytesToInteger：大端
            params[key.decode("latin-1")] = buf[i+5:i+5+n]
            key, i = b"", i + 5 + n
        else:
            key += bytes([buf[i]])
            i += 1
    return params

# 示例（解密后）：methodName\x02\x00\x00\x00\x04test
# parse_frames(...) -> {'methodName': b'test'}
```

若首个长度解析明显超出缓冲区，改按小端 `int.from_bytes(..., "little")` 复核后再解析，以样本首帧长度与实际值对齐为准。

## 变体与关联

- 变体：外层加密器不同（PHP_EVAL_XOR_BASE64 / PHP_XOR_BASE64 / AES 魔改版）只改变密文封装，内层 `0x02` 分帧与调度逻辑不变。
- 变体：插件可多次 includeCode 覆盖同名 `codeName`；也可用 `codeName` 指向 payload 内已有代码段实现复用。
- 关联：[[defense-forensics-godzilla-php-webshell-traffic-decode]]（外层流量解码与 SESSION 两阶段）；[[web-php-rce-godzilla-aes-session-webshell-disguise]]（同一 SESSION payload 机制 + AES 伪装）；[[defense-forensics-godzilla-php-xor-key-md5-bruteforce]]（无密钥时的响应框架 oracle）。

## 检测与防御

- 检测：解密后流量中出现 `0x02` 分隔的二进制键值对、`methodName`/`codeName`/`binCode`/`cmdLine` 等键名；`includeCode` 包后紧跟同 `codeName` 的执行包是插件按需加载的强特征。
- 检测：session 文件中出现大段 PHP 代码或高熵 payload；同一 PHPSESSID 的请求序列呈现“大首包 + 多次小模块包 + 偶发插件包”的节奏。
- 防御：清理马文件与对应 session 文件；对 PHP 进程的 `eval` 行为与会话目录写入做监控；WAF 侧对异常二进制 POST 与固定 MD5 响应框架告警。
