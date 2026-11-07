---
id: web-java-deserialization-openam-jato-clientsession-preauth-rce
title: OpenAM jato.clientSession 认证前反序列化：绕过 jato.pageSession 白名单的替代入口（CVE-2026-33439）
type: scenario
domain: web
path: web/java/deserialization
technique: alternate-entry-whitelist-bypass
aliases:
- CVE-2026-33439
- OpenAM 反序列化
- jato.clientSession
- JATO ClientSession
- CVE-2021-35464 绕过
tags:
- java
- deserialization
- openam
- jato
- pre-auth
- whitelist-bypass
- rce
- gadget
cve:
- CVE-2026-33439
severity: critical
confidence: medium
status: verified
affected_versions: OpenAM 16.0.5 及更早版本（16.0.6 修复）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V35
  verified_at: '2026-11-05T06:08:38+08:00'
  notes: 已对照原文与 11 张图片核对：PWResetUserValidation.jsp 渲染 jato:form；ViewBeanBase 对 jato.pageSession 使用 WhitelistObjectInputStream；jato-2005-05-04.jar 的 ClientSession 构造函数读取 jato.clientSession 并调用 Encoder.deserialize(..., false)（ApplicationObjectInputStream，无白名单）。原文未提供完整 EXP/gadget 执行结果，仅给出 PriorityQueue→ColumnComparator→TemplatesImpl 方向，卡内 confidence=medium 已如实标注。未在本机复现。
---

## 一句话结论

OpenAM 16.0.5 及更早版本只给 `jato.pageSession` 入口加了 `WhitelistObjectInputStream` 白名单，却遗漏了同一 JATO 框架中由 `jato.clientSession` 驱动的 `ClientSession.deserializeAttributes()` 入口；该入口直接调用无白名单的 `Encoder.deserialize()`，攻击者无需认证即可通过 `GET /openam/ui/PWResetUserValidation?jato.clientSession=<序列化 payload>` 触发 `readObject()`，再借 classpath 中的 gadget 链执行任意命令。

## 原理

- OpenAM 的 JSP 页面渲染 `<jato:form>` 标签时，JATO 框架会创建 `ClientSession` 对象；其构造函数从请求参数 `jato.clientSession` 读取 `encodedSessionString`。
- `ClientSession.deserializeAttributes()` 在 attributes 为空时，会执行 `Encoder.deserialize(Encoder.decodeHttp64(this.encodedSessionString), false)`；`Encoder.deserialize()` 内部直接 `new ApplicationObjectInputStream(bais).readObject()`，没有白名单或 JEP 290 过滤器。
- 官方针对 CVE-2021-35464 的修复只覆盖了 `jato.pageSession`：`ViewBeanBase.deserializePageAttributes()` 改用 `IOUtils.deserialise()`，其内部 `WhitelistObjectInputStream.resolveClass()` 对每个类做 `isValidClass` 校验，不在白名单的类抛 `InvalidClassException`。
- 两条路径都位于 JATO 框架、都能从请求参数进入反序列化，但安全校验只挂在应用层封装的 `IOUtils` 上；底层第三方 `jato-2005-05-04.jar` 的 `ClientSession` 仍保留旧的 `Encoder.deserialize()` 调用，形成“修了一个入口、漏了另一个等效入口”的白名单绕过。
- 反序列化 `readObject()` 后，classpath 中存在可用 gadget（原文给出 `PriorityQueue → ColumnComparator → TemplatesImpl` 方向）即可在反序列化阶段触发 `Runtime.exec`，且入口在认证之前。

## 触发条件

- OpenAM 版本为 16.0.5 或更早，且部署包含 JATO 视图层（`jato-2005-05-04.jar`）。
- 存在可匿名访问、会渲染 `<jato:form>` 的页面，如 `/openam/ui/PWResetUserValidation`。
- 请求可携带 `jato.clientSession` 参数；`ClientSession` 构造函数会读取该参数。
- classpath 中存在可用的反序列化 gadget（原文示例为 PriorityQueue/ColumnComparator/TemplatesImpl 组合）。
- 目标未额外部署 JEP 290 全局过滤器或 RASP 阻断。

## 利用步骤

1. 确认目标 OpenAM 版本与页面：访问 `/openam/ui/PWResetUserValidation`，观察是否返回 JATO 表单页面。
2. 审计/确认入口：该页 JSP 渲染 `<jato:form name="PWResetUserValidation" ...>`，JATO 创建 `ClientSession` 并读取 `jato.clientSession`。
3. 构造序列化 payload：以 `PriorityQueue → ColumnComparator → TemplatesImpl` 为方向，将命令执行字节码放入 `TemplatesImpl`，用可比较的 `Comparator` 承载。
4. 对 payload 做 `Encoder.decodeHttp64` 对应的编码（原文为 HTTP64 编码），放入 `jato.clientSession` 参数。
5. 发送未认证请求：`GET /openam/ui/PWResetUserValidation?jato.clientSession=<payload>`；服务端 `readObject()` 触发 gadget，执行命令。
6. 若命令无回显，使用 DNS/HTTP 带外或写入 Web 目录验证。

## PoC

入口请求形态（payload 需按目标编码，以下为占位）：

```http
GET /openam/ui/PWResetUserValidation?jato.clientSession=<HTTP64(serializedPayload)> HTTP/1.1
Host: target
```

关键代码路径（原文核对）：

```java
// jato-2005-05-04.jar: com.iplanet.jato.ClientSession
protected ClientSession(RequestContext context) {
    this.encodedSessionString = context.getRequest().getParameter("jato.clientSession");
}

protected void deserializeAttributes() {
    if (this.attributes == null) {
        if (this.encodedSessionString != null && this.encodedSessionString.trim().length() > 0) {
            this.setAttributes((Map) Encoder.deserialize(
                Encoder.decodeHttp64(this.encodedSessionString), false));
        }
    }
}
```

```java
// JATO Encoder.deserialize：无白名单
ObjectInputStream ois = compressed
    ? new ApplicationObjectInputStream(new InflaterInputStream(bais))
    : new ApplicationObjectInputStream(bais);
Object result = ois.readObject();
```

对照已修复入口：

```java
// ViewBeanBase.deserializePageAttributes：使用 IOUtils -> WhitelistObjectInputStream
setPageSessionAttributes(IOUtils.<Map>deserialise(
    Encoder.decodeHttp64(pageAttributesParam), false, classLoader));
```

原文未提供可直接运行的完整 EXP 字节流，gadget 构造需自行按目标 classpath 适配；本卡 PoC 为入口与代码路径，未实际执行。

## 变体与关联

- 同类模式：修复只覆盖已知参数名/入口，遗漏同一框架的另一个反序列化入口（`clientSession` vs `pageSession`）。
- 变体：若目标对 `jato.pageSession` 有 WAF 规则，可转而使用 `jato.clientSession`；反之亦然。
- 变体：其他 JATO 版本/分支可能保留相同 `Encoder.deserialize`；需按 jar 版本核对。
- 关联卡片：[[web-java-deserialization-filter-rootchecked-first-class-bypass]]（过滤器实现缺陷）、[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]（TemplatesImpl gadget 链）。
- 关联：CVE-2021-35464 为同一产品的 `jato.pageSession` 前身漏洞，本卡是其修复绕过。

## 检测与防御

- 检测：请求参数中出现 `jato.clientSession`/`jato.pageSession`，尤其是 Base64/HTTP64 编码的长字节串；匿名访问 `/openam/ui/*` 并携带异常参数。
- 检测：反序列化异常（`InvalidClassException`、`ClassNotFoundException`）、`ApplicationObjectInputStream` 相关调用栈；JATO 日志中的异常长参数。
- 防御：升级到 OpenAM 16.0.6 或更高版本；确认修复覆盖所有 JATO 反序列化入口，而不只是 `jato.pageSession`。
- 防御：对 `ClientSession`/`Encoder.deserialize` 接入白名单或 JEP 290 全局过滤器；禁止对不可信请求参数反序列化。
- 加固：移除不必要的 JATO 遗留组件；在 WAF/网关层拦截携带序列化参数的匿名请求；对反序列化接口做认证与最小暴露。
- 响应：升级后回归测试两个参数入口；排查历史访问日志中可疑 `jato.clientSession` 请求与异常子进程。
