---
id: web-dotnet-iis-managed-module-backdoor-bin-webconfig
title: IIS 托管模块后门：bin 目录投放 IISModule DLL + web.config 注册 modules，请求即执行命令
type: scenario
domain: web
path: web/dotnet/iis
technique: iis-managed-module-backdoor
aliases:
- IIS 后门
- IIS_backdoor
- web.config modules 后门
- .NET IISModule 后门
- bin DLL 后门
tags:
- iis
- dotnet
- webconfig
- module
- backdoor
- persistence
- webshell
- w3wp
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V291
  verified_at: '2026-11-08T08:08:29+08:00'
  notes: 已对照原文与图31/34-36核对：bin目录IIS_backdoor_dll.dll+web.config modules注册、whoami为iis apppool\defaultapppool、DLL被Easy File Locker设为不可见一致；未实机执行。
---

## 一句话结论

在 IIS 网站的 `bin` 目录放入一个实现 `IISModule` 的托管 DLL，并在 `web.config` 的 `<system.webServer><modules>` 中注册 `type="IIS_backdoor_dll.IISModule"`，之后对该站点的每个请求都会经过该模块，模块按请求参数执行系统命令并以 `w3wp.exe` 的应用池身份返回结果——形成不依赖具体 ASPX 文件的持久化 Web 后门。

## 原理

- IIS 的托管模块（managed module）运行在 ASP.NET 请求管线中，`web.config` 的 `<modules>` 节点把程序集类型注册为模块，IIS 在应用启动时加载 `bin` 目录下的 DLL 并实例化。
- 模块实现 `IHttpModule`（原文示例类型 `IIS_backdoor_dll.IISModule`），可在 `BeginRequest`/`EndRequest` 等事件中读取请求参数（命令、输出），调用 `cmd.exe`/`Process` 执行命令并写回响应。
- 代码以 IIS 工作进程（`w3wp.exe`）身份运行，通常是应用池账户（原文截图 `whoami` 为 `iis apppool\defaultapppool`），权限取决于应用池配置；若应用池使用高权限账户则影响更大。
- 持久化点有两个：`bin\IIS_backdoor_dll.dll` 与 `web.config` 的 modules 注册；应用池回收/站点重启后仍会加载。相比落地 `.aspx` webshell，模块后门不依赖单个可访问页面，且可对所有请求生效，更隐蔽。
- 原文把 DLL 属性设为不可见/不可写/不可删除（文件隐藏），进一步降低被发现概率。

## 触发条件

- 攻击者能向 IIS 站点目录写入文件（`bin` 子目录 + `web.config`），通常通过已有 webshell、文件上传、写权限缺陷或管理员权限。
- 站点运行在 .NET/IIS 环境，允许加载自定义托管模块（默认允许；若 `web.config` 被锁定或 `modules` 节被策略禁止则失败）。
- 攻击者能编译或获取与目标 .NET 版本兼容的模块 DLL；应用池身份决定命令执行权限。
- 模块需处理请求路由，避免破坏正常站点功能。

## 利用步骤

1. 在网站根目录新建 `bin` 文件夹，放入编译好的 `IIS_backdoor_dll.dll`。
2. 新建或修改 `web.config`，在 `<systemWebServer>` 下注册模块：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <modules>
            <add name="IIS_backdoor" type="IIS_backdoor_dll.IISModule" />
        </modules>
    </system.webServer>
</configuration>
```

3. 访问站点，使用配套的 `IIS_backdoor_shell` 客户端填写目标 URL 与命令，模块执行命令并回显。
4. 用 `whoami` 确认权限（原文为 `iis apppool\defaultapppool`）。
5. 需要隐蔽时给 DLL 加隐藏/系统/只读属性，或把模块名伪装成正常模块。

## PoC

`web.config`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <modules>
            <add name="IIS_backdoor" type="IIS_backdoor_dll.IISModule" />
        </modules>
    </system.webServer>
</configuration>
```

目录结构：

```text
C:\inetpub\wwwroot\
├── bin\IIS_backdoor_dll.dll
└── web.config
```

客户端：填写 `http://target`、命令 `whoami`，返回 `iis apppool\defaultapppool`。

## 变体与关联

- 变体：模块名/类型伪装成系统模块（如 `System.Web...`）；DLL 用强名称/签名伪造或侧加载真实载荷。
- 变体：通过 `GAC` 安装或 machine.config 全局注册模块，影响同一服务器上的所有站点。
- 关联：[[web-dotnet-iis-webdav-put-move-webshell]] 是 IIS WebDAV 写文件落地 ASP webshell 的初始访问手法；本卡是拿到写权限后的模块级持久化。
- 关联：[[pentest-persistence-windows-reserved-device-name-webshell]] 是另一种 IIS 可解析但难删除的 webshell 形态。

## 检测与防御

- 检测：`web.config`/`machine.config` 中 `modules` 节新增的未知 `type`；站点 `bin` 目录出现未签名/非业务 DLL；`w3wp.exe` 创建 `cmd.exe`/`powershell.exe` 子进程（Sysmon 1/11）；模块对每个请求都执行异常逻辑。
- 防御：对站点目录设置严格写权限；启用 IIS 配置锁定（`web.config` 节锁定）；应用池使用低权限账户；对 `bin` DLL 做代码签名/完整性校验（WDAC/AppLocker）；监控 `w3wp` 子进程与 web.config 变更。
