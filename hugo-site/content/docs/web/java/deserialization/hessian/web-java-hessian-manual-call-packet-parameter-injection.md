---
id: web-java-hessian-manual-call-packet-parameter-injection
title: 手搓 Hessian 1.0 业务调用包：c/m/S 结构与长度回填改参数做注入测试
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian-manual-call-packet-parameter-tamper
tags:
- java
- hessian
- protocol
- rce
- sqli
- pentest
- binary-rpc
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V603
  verified_at: '2026-11-12T18:23:35+08:00'
  notes: 已对照原文通读并逐张核对 4/4 图（帧结构标注 c12m/00 10/S/00 38/结束符 z、外网请求与响应、hex dump 63 02 00 6d 00 10 ... 53 00 38 ... 7a、python len()=56 均与正文一致）。修正两处版本字节错误：①Python PoC 由 b"c\x01\x02m" 改为原文抓包/hex dump 的 b"c\x02\x00m"；②说明中“实测版本字节 12（Hessian 1.2）”改为 02 00，并把“版本用于选择 HessianInput/HessianOutput”订正为仅选择输出实现（首字节>=2 用 Hessian2Output，否则 HessianOutput，输入固定 HessianInput）；可读形式同步改为 c 02 00 并注明原文配图简写为 12（staging 草稿同步修改）。未验证点：未在本地重放该帧；原文未给组件版本，affected_versions 留空正确。dedup：与 hessianservlet-argument-header-entry、hessian2-protocol-error、map-put 等反序列化入口卡协议骨架相同但目的/触发不同（正常业务参数注入 vs readObject RCE），非同链，保留。
url: /docs/web/java/deserialization/hessian/web-java-hessian-manual-call-packet-parameter-injection/
draft: false
kb_aliases:
- Hessian 包结构
- c12m 请求包
- Hessian 手工构造请求
- Hessian 参数注入
- Hessian 长度回填
- readMethod S 字符串
- Hessian SQL 注入测试
---

## 一句话结论

Hessian 1.0 的业务调用请求是二进制帧：`c`（0x63）+ 两字节版本 + `m`（0x6d）+ 两字节方法名长度 + 方法名 + 参数（字符串为 `S` 0x53 + 两字节长度 + 内容）+ `z`（0x7a）结束；没有官方客户端时按该结构手搓请求，把参数值替换成注入 payload 并同步修改长度字段（长度可大于等于 payload，多余用空格或注释占位），就能像普通 HTTP 请求一样在 Repeater/脚本里测试 Hessian 接口的 SQL 注入、越权等业务参数问题。

## 原理

- **入口分支**：HessianServlet 只接受 POST，读首字节判断协议：`H`（72）= Hessian 2.0，进入 `createHessian2Input`；`c`（99）= Hessian 1.0 调用，随后读两字节版本（原文抓包为 `02 00`；解析时只在首字节 `var10 >= 2` 时把输出选为 `Hessian2Output`，否则 `HessianOutput`，输入始终是 `HessianInput`，并不校验具体版本号）。Hessian 2.0 分支是经典反序列化入口（另一类问题）；本卡讲 `c` 分支的业务调用。
- **方法名编码**：`HessianSkeleton.invoke` 调 `in.readMethod()`：期望 `m`（109），再读两字节大端长度 `d1*256+d2`，读取该长度的字符作为方法名。`AbstractSkeleton` 初始化时把接口方法存为 `方法名__参数个数` 与 `方法名` 两种键，因此方法名可用 `getmodelCodeInfo` 或 `getmodelCodeInfo__1` 形式。
- **参数编码**：`in.readObject(args[i])` 按参数类型解析。字符串标签 `S`（83，末块）/`s`（115，分块），随后两字节长度与 UTF-8 内容；`S` 表示字符串结束。其他常用标签：`I` 整数、`L` 长整型、`N` null、`M` map、`V` list、`T`/`F` 布尔、`D` 日期等。
- **结束符**：调用结束由 `readEnd()` 校验 `z`（122）。完整帧形如：
  `63 02 00 6d <len2> <method> 53 <len2> <arg> 7a`
- **长度字段是“步长”**：解析器严格按长度字段读取；参数值长度变化后必须同步改长度字段，否则后续字节错位（把内容读到别处/报错）。反过来，长度也可以设置得比实际 payload 大——解析器会继续读取后续字节凑数，因此实践中“长度 >= payload 长度”即可，多余位置用空格或 SQL 注释（`-- `、`/*...*/`）填充，不破坏语义。
- **为什么可复用**：Hessian 是二进制协议，Burp 默认只能改文本；理解帧结构后可以直接在十六进制编辑器/脚本里替换参数，服务端仍按正常 RPC 处理，业务层 SQL 拼接/越权等问题照常触发。

## 触发条件

- 目标暴露 Hessian 服务（`*.hessian` servlet 映射、`HessianSpringInvokeService` 或自定义 Servlet 包装 HessianSkeleton），且接口可访问。
- 能获得一个合法调用样本（客户端抓包、源码、错误回显）以得知方法名与参数个数/类型。
- 业务方法把参数拼接进 SQL/命令/模板（注入类问题）或缺少权限校验（越权类问题）。

## 利用步骤

1. 抓取一个合法 Hessian 请求（或从源码/接口文档得到方法名，如 `getmodelCodeInfo`、参数 1 个字符串）。
2. 按帧结构切分：首字节 `c`、版本两字节、`m` + 两字节长度 + 方法名、参数标签与两字节长度、结尾 `z`。
3. 把参数字符串替换为 payload（如 `' union select USER,NULL,NULL,NULL,NULL from dual -- sd`），计算新长度写回两字节字段；长度不足会截断，长度偏大则用空格/注释补齐。
4. 在 Burp Repeater（Hex 视图）或 Python socket 中重放；`Content-Type: application/x-www-form-urlencoded` 也能被部分实现接受（原文即普通表单 Content-Type）。
5. 看响应：Hessian 响应为二进制（`HDR0...`/`r...`）；原文注入后返回的字符串字段变为 `HDR0ZXJ...null.null.null`，证明 SQL 已执行。
6. 对多参数方法逐个参数替换并同步各自长度；对象/Map 类型参数需按对应标签编码（可先用官方客户端生成样本再改其中字符串）。

## PoC

原文帧（hex，方法名 `getmodelCodeInfo`，长度 `0x0010`；参数 SQL 注入长度 `0x38`=56）：

```text
63 02 00 6d 00 10 67 65 74 6d 6f 64 65 6c 43 6f 64 65 49 6e 66 6f
53 00 38 27 20 75 6e 69 6f 6e 20 73 65 6c 65 63 74 20 55 53 45 52
2c 4e 55 4c 4c 2c 4e 55 4c 4c 2c 4e 55 4c 4c 2c 4e 55 4c 4c 20 66
72 6f 6d 20 64 75 61 6c 20 2d 2d 20 73 64 7a
```

可读形式（原文配图把版本字节标注为 `12`，实际抓包为 `02 00`）：

```text
c 02 00 m 00 10 "getmodelCodeInfo" S 00 38 "' union select USER,NULL,NULL,NULL,NULL from dual -- sd" z
```

发送示例（Python，长度用计算值回填）：

```python
import socket
method = b"getmodelCodeInfo"
arg = b"' union select USER,NULL,NULL,NULL,NULL from dual -- sd"
body = b"c\x02\x00m" + len(method).to_bytes(2, "big") + method \
     + b"S" + len(arg).to_bytes(2, "big") + arg + b"z"
req = (b"POST /admin.license/EncryptService.hessian HTTP/1.1\r\n"
       b"Host: target\r\nContent-Type: application/x-www-form-urlencoded\r\n"
       + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
s = socket.create_connection(("target", 8080)); s.sendall(req); print(s.recv(4096))
```

说明：原文抓包版本字节为 `02 00`（首字节 2 时输出走 `Hessian2Output`），解析只按该值选择输出实现、不校验具体版本号；方法名与业务接口需按目标替换。

## 变体与关联

- 变体：Hessian 2.0（`H` 开头）分支不做业务调用而是反序列化，属另一类入口（见关联卡）。
- 变体：长度字段填入比 payload 更大的值并用空格/注释占位（原文总结的“步长 >= payload 长度”技巧），可规避某些长度校验或让 payload 边界更灵活。
- 变体：多参数/对象参数时按 `V`（list）、`M`（map）等标签编码；可用 Hessian 客户端生成合法帧后再定位并替换字符串片段。
- 关联：[[web-java-deser-hessian-hessianservlet-argument-header-entry]]（同一协议骨架 `c 02 00 + m/H`，但目标是方法参数/Header 的 readObject 反序列化 RCE；本卡讲正常业务调用与参数注入）；[[web-java-deser-hessian2-protocol-error-tostring-trigger]]、[[web-java-deser-hessian-deserialization-entry-map-put]]（Hessian 反序列化入口）。
- 边界：服务端启用自定义 SerializerFactory 白名单/加密传输、方法名不存在或参数类型不匹配、长度字段计算错误时帧解析失败；业务层已参数化查询时 SQL 注入不成立，但越权/逻辑问题仍需单独验证。

## 检测与防御

- 业务层：SQL 参数化、命令/模板参数白名单，不信任 RPC 参数；接口按角色鉴权，避免匿名调用内部服务。
- 协议层：对 Hessian 接口做来源 IP/认证限制；升级 Hessian 并启用 SerializerFactory 白名单；对方法名与参数长度做合理性校验。
- 检测：请求体首字节 `c`（0x63）且含 `m`/`S` 结构的二进制流量；参数中出现 SQL/命令关键字；WAF 需解析二进制协议而非仅匹配文本；同一接口出现方法名与实际业务不符、长度字段与实际内容不一致的请求。
