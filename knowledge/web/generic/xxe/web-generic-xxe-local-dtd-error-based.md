---
id: web-generic-xxe-local-dtd-error-based
title: 无外网盲 XXE：重定义目标本地 DTD 参数实体并借报错回显读取文件
type: scenario
domain: web
path: web/generic/xxe
technique: xxe-local-dtd-error-based-file-read
aliases:
- 本地 DTD 报错回显
- local DTD XXE
- dtd-finder
- 无外网盲 XXE
- XXE 错误信息外带
tags:
- xxe
- blind-xxe
- error-based
- local-dtd
- no-egress
- file-read
- java
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V371
  verified_at: '2026-11-09T05:53:46+08:00'
  notes: 已对照原文核对；图03 即 WebSphere sip-app_1_0.dtd 本地 DTD 重定义 %condition 的请求/响应示例（FileNotFoundException 带 /etc/passwd 内容），与卡内 PoC 一致；原文仅引用公开方法与 dtd-finder 链接、未自行复现，卡内 confidence=medium 并注明，保留
---

## 一句话结论

盲 XXE 且目标无法出网（不能引用攻击者 DTD）时，可以引用目标系统上已存在的本地 DTD 文件，利用“同名实体只取第一次定义”的规则重定义该 DTD 内部使用的参数实体，把文件内容嵌入一个故意触发异常的实体中，让解析错误信息把文件内容带回响应。

## 原理

- **本地 DTD 是现成的“远程 DTD”替身**：许多系统/应用自带 `.dtd` 文件（WebSphere、Tomcat、Spring、Hibernate 等），路径可预测；`<!ENTITY % local_dtd SYSTEM "file:///已知/路径.dtd">` 让解析器从本机加载它。
- **实体常量与覆盖规则**：XML 实体是常量，同名实体只有第一次定义生效；在 DOCTYPE 内部子集里先重定义该 DTD 将要使用的某个参数实体（如 `%condition;`），再 `%local_dtd;` 引入 DTD，DTD 展开时用的就是攻击者的定义。
- **把文件拼进错误信息**：重定义的内容里嵌套 `%file;`（读目标文件）与 `%error;`（构造一个指向不存在文件的 SYSTEM 实体），解析器在处理错误实体时抛出 `FileNotFoundException`，异常消息里带上了 `%file;` 的内容，应用若把异常回显给用户，文件内容即被带出。
- **为什么需要本地 DTD**：攻击者无法托管远程 DTD（无出网/防火墙）时，本地 DTD 提供了合法的 DTD 语法上下文与可被覆盖的参数实体名；能否成功取决于目标是否安装了已知 DTD、解析器是否允许外部参数实体、以及异常是否回显。

## 触发条件

- 目标为 Java 等使用外部 DTD 的 XML 解析器，允许 DOCTYPE 与外部参数实体。
- 目标存在可读的已知本地 DTD（路径可通过指纹、源码、常见中间件默认安装路径确定）。
- 应用会把解析异常/错误信息返回给客户端（或错误页面含异常栈）。
- 目标不能出网或远程 DTD 被阻断（本手法主要用于这种场景）。

## 利用步骤

1. 判断目标中间件/框架（响应头、错误页、已知产品指纹），用公开的本地 DTD 路径清单或 `dtd-finder` 类工具枚举可用 DTD 路径。
2. 构造 XML：先 `<!ENTITY % local_dtd SYSTEM "file:///目标/本地.dtd">`，在内部子集里重定义该 DTD 会引用的参数实体（常见如 `%condition;`）。
3. 重定义内容中嵌套 `%file;`（读目标文件）与 `%error;`（引用不存在的文件触发异常），再 `%local_dtd;`。
4. 提交 XML，观察响应中的 `FileNotFoundException` 或解析错误信息，其中应包含文件内容。
5. 若异常未回显，尝试不同的错误触发点/参数实体名，或改用带内/出网外带通道。

## PoC

以 WebSphere 自带的 `sip-app_1_0.dtd` 为例（路径与实体名随目标软件版本变化）：

```xml
<?xml version="1.0" ?>
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///opt/IBM/WebSphere/AppServer/properties/sip-app_1_0.dtd">

  <!ENTITY % condition 'aaa)>
      <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
      <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
      &#x25;eval;
      &#x25;error;
      <!ELEMENT aa (bb'>

  %local_dtd;
]>
<message>any text</message>
```

预期响应中出现类似：

```text
java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash
...
```

## 变体与关联

- **工具化枚举**：GoSecure 的 `dtd-finder` 收录了大量系统/应用默认 DTD 路径与可覆盖实体名；也可手工按中间件版本查默认安装路径。
- **错误回显通道**：与 PortSwigger 的 error-based XXE 同源，但用本地 DTD 替代远程 DTD，解决无出网问题。
- **有出网时**：直接用远程 DTD + 参数实体 OOB，见 [[web-generic-xxe-oob-exfil]]；有回显时用 [[web-generic-xxe-inband-file-read-default-insecure]]。
- **边界**：目标没有已知本地 DTD、解析器禁用参数实体、异常被统一包装不含消息、或文件内容含破坏 DTD 语法的字符时失败；原文仅总结该思路并引用公开研究，未给出自身环境复现，实际可用性需按目标验证。

## 检测与防御

- **解析器加固**：禁用 DOCTYPE 与外部实体/外部参数实体，从根本上消除所有 DTD 加载。
- **错误处理**：不要把解析异常原文返回给客户端，统一错误页与日志脱敏。
- **检测**：请求中出现 `local_dtd`、`file:///...dtd`、`&#x25;file`、`&#x26;#x25;error` 等特征；响应错误信息中出现 `/etc/passwd`、`win.ini` 等文件内容；Java 进程读取异常 DTD 路径。
- **最小权限**：限制 Web 进程可读文件范围，降低本地 DTD 与敏感文件的暴露面。
