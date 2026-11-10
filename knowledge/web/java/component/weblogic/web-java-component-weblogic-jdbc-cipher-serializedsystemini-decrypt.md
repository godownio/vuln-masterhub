---
id: web-java-component-weblogic-jdbc-cipher-serializedsystemini-decrypt
title: WebLogic 域内 JDBC 连接密文解密：读 jdbc xml + SerializedSystemIni.dat 还原数据库口令
type: scenario
domain: web
path: web/java/component/weblogic
technique: weblogic-serializedsystemini-jdbc-cipher-decrypt
aliases:
- SerializedSystemIni.dat 解密
- WebLogic 数据库口令解密
- jdbc xml 密文 {AES}
- WebLogic 密码解密工具
- WebLogic 连接字符串泄露
- weblogic 密文两类
tags:
- weblogic
- credential-leak
- decrypt
- jdbc
- database
- lateral-movement
- java
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:39:27+08:00'
  notes: 已对照原文与图10/11/12/13核对：jdbc 配置路径 /root/Oracle/Middleware/user_projects/domains/base_domain/config/jdbc/JDBC_Data_Source-0-3407-jdbc.xml 与 SerializedSystemIni.dat 默认位置同域 security/ 一致；图11 解密工具输入 dat 与密文 {AES}ZhArsOkXPBA9AvAwRxNxpK4G0WIHIpNFBZVsu+PDIYU= 得 Meetsec#1024，与卡内密文和明文逐字一致。未验证点：原文 jdbc xml 中的 <url>/<user>/<password> 片段为卡内按形态补齐，原文仅说明「拿到用户名 root 和 AES 加密后的密码」；未复跑解密；原文未给 WebLogic 版本（图08 系 CVE-2020-2551 靶场），未设 affected_versions。
---

## 一句话结论

拿到 WebLogic 主机的文件读/命令执行权限后，`user_projects/domains/<domain>/config/jdbc/*.xml` 里的数据源配置以 `{AES}...` 密文形式保存数据库用户名与口令，而解密密钥就落在同域 `security/SerializedSystemIni.dat` 中；把两个文件一起取出离线解密，即可得到明文数据库口令，直接连数据库拖数据或把该凭据用于横向。

## 原理

- WebLogic 把「数据库连接用户名/口令」和「console 管理员口令」都做加密存储，避免明文落盘：数据源描述文件位于 `config/jdbc/` 下的 `*-jdbc.xml`，口令字段形如 `{AES}<base64 密文>`。
- 解密所需的主密钥保存在域级 `security/SerializedSystemIni.dat`（二进制序列化文件，域创建时生成，全局唯一），由它派生出 AES 等算法所需的密钥材料；因此**只有密文没有这个 dat 文件解不开**，反之只要这两个文件都在手，就能离线还原。
- 之所以成立：WebLogic 的威胁模型假设域目录只有管理员可读，未考虑「攻击者已经拿到该主机的文件读权限」；一旦突破到文件系统，加密只是增加一步，而不是边界。
- 密文带有 `{AES}` 前缀标识算法，便于选择对应的解密实现；不同 WebLogic 版本会追加版本号/算法标识，但 dat 文件与密文的配对关系不变。
- 解密后的口令一般能直接登录内网数据库（本例第二台机器的 MySQL），且这类 DB 账号常带较高权限，可继续读业务数据或借 `load_file` 之类的 DB 能力扩大影响。

## 触发条件

- 已获得 WebLogic 主机上的文件读取或命令执行（反序列化 RCE、弱口令后台、任意文件读）。
- 目标为域模式部署，`user_projects/domains/<domain>/` 可读，其中同时存在 `config/jdbc/*-jdbc.xml` 与 `security/SerializedSystemIni.dat`。
- 存在使用数据库的数据源配置（否则 jdbc 目录为空）。
- 解密工具/实现可用（离线运行，无需在目标上执行）。

## 利用步骤

1. 定位域目录：常见 `$WL_HOME/user_projects/domains/<domain>/`；确认 `config/jdbc/` 下有 `*-jdbc.xml`。
2. 读取任一 jdbc xml，取出 `<url>`（含数据库地址与库名）、`<user>` 与加密的 `<password>`；口令值以 `{AES}` 开头说明需要 dat 文件。
3. 读取 `security/SerializedSystemIni.dat`（同域目录），与 jdbc xml 一并下载到本地（可用 webshell 回显、DNS 外带或 base64 分块传输）。
4. 用 WebLogic 口令解密工具/脚本指定 `SerializedSystemIni.dat` 与密文，得到明文口令。
5. 用取到的地址、用户名、明文口令直连数据库（本地客户端或经代理/隧道），验证读写权限。
6. 若数据库不可直连，用同一凭据在目标机内连接、或用数据库自身能力（`load_file` 等）读文件，再把结果带回。

## PoC

```text
# 需要取出的两份材料（路径按版本/域名为准）
/root/Oracle/Middleware/user_projects/domains/base_domain/config/jdbc/JDBC_Data_Source-0-3407-jdbc.xml
/root/Oracle/Middleware/user_projects/domains/base_domain/security/SerializedSystemIni.dat
```

```xml
<!-- jdbc xml 片段形态 -->
<jdbc-data-source>
  <name>JDBC_Data_Source-0-3407</name>
  <jdbc-driver-params>
    <url>jdbc:mysql://db-host:3306/data</url>
    <driver-name>com.mysql.jdbc.Driver</driver-name>
    <properties>
      <property><name>user</name><value>root</value></property>
      <property><name>password</name><value>{AES}ZhArsOkXPBA9AvAwRxNxpK4G0WIHIpNFBZVsu+PDIYU=</value></property>
    </properties>
  </jdbc-driver-params>
</jdbc-data-source>
```

```text
# 离线解密：工具选择 SerializedSystemIni.dat + 粘贴 {AES} 密文
文件: SerializedSystemIni.dat
密文: {AES}ZhArsOkXPBA9AvAwRxNxpK4G0WIHIpNFBZVsu+PDIYU=
结果: Meetsec#1024
```

```bash
# 用还原出的凭据连库（经代理/隧道后本地执行）
mysql -h db-host -P 3306 -u root -p'Meetsec#1024' data -e "select load_file('/flag');"
```

## 变体与关联

- 变体：console 管理员口令同样由 `SerializedSystemIni.dat` 保护，从 `boot.properties`/`config.xml` 取密文可还原 console 口令。
- 变体：`{3DES}`、`{AES256}` 等不同前缀对应不同算法，工具需按前缀选实现；dat 文件缺失时可从同域备份/其它节点取。
- 变体：只有文件读不能下载二进制时，用 base64 分块经 webshell 回显或 DNS/HTTP 外带取出 dat（约几十 KB 级）。
- 关联：`[[web-java-component-weblogic-cve-2020-2551-iiop-echo-rce]]` 是进入 WebLogic 主机的常见入口，本卡是其后的凭据收割环节；`[[pentest-lateral-movement-bladex-datasource-plaintext-credential-db-takeover]]` 是「后台回显明文口令」的对照形态（无需解密）。
- 边界：域目录不可读、dat 文件被删除或迁移、数据源使用外部凭据库/集成认证（口令不落盘）、数据库仅允许应用服务器白名单访问时，链断或降级。

## 检测与防御

- 检测：WebLogic 进程/子进程访问 `config/jdbc/*-jdbc.xml` 与 `security/SerializedSystemIni.dat`（尤其成对读取）；异常下载 dat 二进制；随后内网数据库出现来自非应用服务器的登录。
- 修复：域目录与 dat 文件权限收紧到最小服务账号（0700/属主唯一），禁止 Web 应用进程读 dat；数据库账号最小权限，禁止 root/DBADMIN 级别的数据源账号。
- 加固：数据库只允许应用服务器 IP 访问并强制 TLS；对 `SerializedSystemIni.dat` 的访问做文件完整性/访问审计并告警；定期轮换数据源口令。
