---
id: web-java-deserialization-templatesimpl-stub-param-defineclass-secondload
title: 反序列化 payload 长度受限时用 TemplatesImpl 轻量 stub 经 request 参数 defineClass 二次加载内存马
type: scenario
domain: web
path: web/java/deserialization
technique: two-stage-defineclass-loader
aliases:
- 两段式类加载缩短 payload
- defineClass 二次加载内存马
tags:
- java
- deserialization
- templatesimpl
- memshell
- defineclass
- length-limit
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-33
  verified_at: '2026-11-08T17:13:35+08:00'
  notes: 已对照原文核对：4916字节超限（img02）、去transform后3260字节（img03）、POST /deserialize data+c 双参数（img04）、访问/e回显dir结果实测成功（img05）；两段式defineClass流程与原文代码一致。小差异：原文最终内存马类代码从header c取命令，img05实测截图为body参数cmd=dir，两版本均原文出现，不影响链成立
---

## 一句话结论

反序列化入口限制 payload 长度（本题 6000 字符，Tomcat Embed 还有 header 8K/body 2M 限制）时，先把 CC 链改为 TemplatesImpl 加载一个仅约 3KB 的 stub 类，其 static 块从当前 HTTP 请求参数取 base64 字节码经 defineClass 二次加载并实例化真正的内存马，payload 主体改为经参数传输，绕过长度限制。

## 原理

TemplatesImpl 的 _bytecodes 被加载时会实例化 AbstractTranslet 子类并执行其 static 块/构造器，这本身只需要很短的类。stub 类在 static 块里通过 RequestContextHolder 拿到当前 request（反射 request→response 字段），读参数 c 的 base64，反射调用 ClassLoader.defineClass 加载字节码并 newInstance——真实内存马（如 Spring Controller 马）的字节码全部走 HTTP 参数传递，不占反序列化 payload 长度。同时二次 defineClass 的类可以调用任意 Runtime.exec 等，黑名单只过滤序列化流中出现的类名字符串，参数里的字节码不受黑名单检查（黑名单是对 base64 解码后的可见字符串做的，需注意字节码中不含 Runtime 等字面量——如用 exec(String[]) 且代码中避免直接出现被拦关键字）。

## 触发条件

- 存在可打 TemplatesImpl 的反序列化链（如 CC11：LazyMap+TiedMapEntry+InvokerTransformer("getOutputProperties")，无需 ChainedTransformer）；
- 反序列化发生在 HTTP 请求线程内（RequestContextHolder 可用）；
- payload 长度受限（应用限制、header 8K、body 2M 等）。

## 利用步骤

1. 构造 stub 类 L extends AbstractTranslet：static 块内取 request、反射取 response、Base64 解码参数 c、defineClass 加载并 `c.newInstance().equals(new Object[]{r,s})` 传参；Javassist 删除两个 transform 方法（4916→3260 字节）；
2. 用 L 的字节码构造 CC11 链（LazyMap.decorate + TiedMapEntry + InvokerTransformer("getOutputProperties") 驱动 TemplatesImpl），base64 后作为 data 参数 POST /deserialize；
3. 把 Controller 型内存马类 E 的字节码（RequestMappingHandlerMapping.registerMapping 注册 /e 路由执行命令）base64 后放参数 c 一并提交；
4. 访问 /e（命令取自 header c）回显执行结果（原文实测 dir 列目录成功）。

## PoC

```
POST /deserialize
data=<CC11+stub 的 base64>&c=<内存马类字节码的 base64>
GET /e  （Header: c: dir）
```

原文 miniLCTF 2025 ezCC（Spring Boot 2.7.4/JDK8，CC3.2.1）实测打通并回显命令结果。

## 变体与关联

- 与 Shiro rememberMe 8KB 头限制的两段式 ShellLoader 同一思想，但入口为任意反序列化点、类字节码经 GET/POST 参数传递；
- stub 中还可嵌套 RMIConnector 等更大 payload，因字节码走参数不受限；
- 该模式天然把"反序列化链"与"内存马"解耦成节点，便于组合复用。

## 检测与防御

- 检测：反序列化防护点之外，监控 defineClass 反射调用与 RequestMappingHandlerMapping.registerMapping 动态注册；URL 参数中携带大段 base64（可按字节码 magic 前缀 ac ed 识别）。
- 防御：反序列化白名单 resolveClass；禁止对不可信数据 readObject；升级并限制 TemplatesImpl 可达链。
