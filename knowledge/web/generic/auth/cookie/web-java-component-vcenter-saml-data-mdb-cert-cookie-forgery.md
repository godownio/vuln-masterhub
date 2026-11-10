---
id: web-java-component-vcenter-saml-data-mdb-cert-cookie-forgery
title: vCenter SAML Cookie 伪造：从 data.mdb 提取 IdP/信任证书，离线签发 VSPHERE-UI-JSESSIONID 管理员会话
type: scenario
domain: web
path: web/generic/auth/cookie
technique: vcenter-saml-data-mdb-cert-cookie-forgery
aliases:
- vCenter SAML Cookie 伪造
- data.mdb 提取证书
- VSPHERE-UI-JSESSIONID
- vCenter_GenerateLoginCookie
- vCenter_ExtraCertFromMdb
- vSphere Client 管理员 Cookie
- vCenter 登录绕过
tags:
- web
- java
- vmware
- vcenter
- saml
- cookie-forgery
- authentication-bypass
- data-mdb
- idp-cert
- post-exploitation
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V303
  verified_at: '2026-11-08T11:35:58+08:00'
  notes: '已对照原文与图08-16核对：data.mdb 路径、python-ldap 编译失败、1.py 提取 idp_cert/trusted_cert 与 Domain: vsphere.local、2.py 获取 VSPHERE-UI-JSESSIONID=B46EDD4F...、刷新 403 与访问 /ui 进入 vSphere Client(256 VM/59 主机) 均与原文一致；未复现，未验证其他版本断言格式差异'
---

## 一句话结论

取得 vCenter 主机 root 后，下载 `/storage/db/vmware-vmdir/data.mdb`（Windows 为 `C:\ProgramData\VMware\vCenterServer\data\vmdird\data.mdb`），用 `vCenter_ExtraCertFromMdb.py` 提取 IdP 证书/私钥与两个 trusted cert（并读出 Domain，通常 `vsphere.local`），再用 `vCenter_GenerateLoginCookie.py` 构造并签名 SAML assertion、向 vCenter 换取 `VSPHERE-UI-JSESSIONID` 管理员 Cookie；浏览器添加 Cookie 后不要刷新，直接访问 `https://<ip>/ui` 即进入 vSphere Client。

## 原理

- **证书存放位置**：vCenter 的 SSO/SAML 身份提供者（IdP）证书与信任证书存放在 VMware Directory Service 的 `data.mdb` 中：
  - Linux：`/storage/db/vmware-vmdir/data.mdb`；
  - Windows：`C:\ProgramData\VMware\vCenterServer\data\vmdird\data.mdb`。
  该文件包含 IdP 的证书与私钥、以及用于验证 SAML 的 trusted cert 链。
- **为什么能伪造 Cookie**：vCenter 的 Web SSO 用 SAML 断言登录。拿到 IdP 私钥和受信证书后，攻击者可以离线为一个任意主体（如 `Administrator@vsphere.local` 或域管理员）签发合法的 SAML assertion，再向 vCenter 的 `/websso/SAML2/SSO/...` 提交，换取 UI 会话 Cookie `VSPHERE-UI-JSESSIONID`；服务端只验证签名/证书链，签名由攻击者用偷来的 IdP 私钥完成，因此通过。
- **脚本一：`vCenter_ExtraCertFromMdb.py`**：解析 `data.mdb`，输出 `idp_cert.txt`（含 `BEGIN PRIVATE KEY` 与证书）、`trusted_cert_1.txt`、`trusted_cert_2.txt`，并打印 `CN=...TrustedCertChain-1...`、`Domain: vsphere.local`。
- **脚本二：`vCenter_GenerateLoginCookie.py`**：参数为目标 IP/域名、Domain、三个证书文件；流程为 Initiating SAML request → Generating SAML assertion → Signing the SAML assertion → Attempting to log into vCenter → 输出 `Successfully obtained Administrator cookie` 与 `VSPHERE-UI-JSESSIONID=...`。
- **常见坑**：
  - `pip3 install -r requirements.txt` 编译 `python-ldap` 失败（缺 `lber.h`）；改用 3gstudent 的纯 Python 脚本，省去环境依赖。
  - `data.mdb` 很大（原文 20MB+）时下载慢/分析失败：可以把脚本上传到目标服务器上运行，只带回三个证书文件。
  - 添加 Cookie 后不要直接刷新页面（会 403），应访问 `https://<ip>/ui` 进入 HTML5 vSphere Client。
- **前置条件**：需要能读 `data.mdb` 的 root/管理员权限（通常由 CVE-2021-22005 等 getshell 提供），以及网络可达 vCenter 的 443。

## 触发条件

- 已控制 vCenter 主机（root/administrator）并能读取 `data.mdb`；或能通过任意文件读取/备份拿到该文件。
- 知道 vCenter 的地址与 SSO Domain（通常 `vsphere.local`）；有可用的 `idp_cert.txt` 与 trusted cert 文件。
- 网络可达 vCenter HTTPS（443），且 SSO 登录端点未被额外 MFA/客户端证书保护。
- 仅用于授权测试。

## 利用步骤

1. **取 data.mdb**：用 Webshell/文件管理器下载 `/storage/db/vmware-vmdir/data.mdb`；若文件太大，直接上传脚本到目标运行。
2. **提取证书**：`python3 vCenter_ExtraCertFromMdb.py data.mdb`，得到 `idp_cert.txt`、`trusted_cert_1.txt`、`trusted_cert_2.txt`，记录输出的 `Domain:`。
3. **生成 Cookie**：`python3 vCenter_GenerateLoginCookie.py <vcenter_ip> <vcenter_ip> vsphere.local idp_cert.txt trusted_cert_1.txt trusted_cert_2.txt`，等待输出 `VSPHERE-UI-JSESSIONID=...`。
4. **注入 Cookie**：浏览器 F12 → Application/存储 → Cookies → 在 vCenter 域名下新增 `VSPHERE-UI-JSESSIONID`，值填上一步的 Cookie。
5. **进入控制台**：不要刷新当前登录页，直接访问 `https://<ip>/ui`；成功则进入 vSphere Client（原文可见 256 台 VM、59 台主机）。
6. **失败排查**：检查 Domain 是否与 SSO 配置一致、证书文件是否完整、目标地址是否与 Cookie 的域匹配、Cookie 是否过期；重新提取/重新生成。

## PoC

```bash
# 1) 从 data.mdb 提取 IdP/trusted 证书（3gstudent 脚本）
python3 vCenter_ExtraCertFromMdb.py data.mdb
# 输出：idp_cert.txt / trusted_cert_1.txt / trusted_cert_2.txt
#       Domain: vsphere.local

# 2) 生成管理员 Cookie
python3 vCenter_GenerateLoginCookie.py 10.x.x.x 10.x.x.x vsphere.local \
    idp_cert.txt trusted_cert_1.txt trusted_cert_2.txt
# 输出：Successfully obtained Administrator cookie
#       Cookie: VSPHERE-UI-JSESSIONID=...

# 3) 浏览器添加 Cookie 后访问
https://10.x.x.x/ui
```

原文实测：`python3 1.py data.mdb` 成功提取 IdP 证书与两个 trusted cert；`python 2.py ...` 输出 `Successfully obtained Administrator cookie for 10.x.x.x` 和 `VSPHERE-UI-JSESSIONID=B46EDD4F733E9BD6CF94FA4...`；添加 Cookie 后访问 `/ui` 进入 vSphere Client。

## 变体与关联

- **Windows vCenter**：`data.mdb` 路径为 `C:\ProgramData\VMware\vCenterServer\data\vmdird\data.mdb`；提取/生成脚本参数相同，注意在 Windows 上运行 Python 或把文件带回分析机。
- **其它 SAML 工具**：horizon3ai 的 `vcenter_saml_login.py` 也能做类似事情，但依赖 `python-ldap`（编译失败时改用 3gstudent 脚本）；不同 vCenter 版本对断言格式/证书链要求不同。
- **前置 getshell**：[[web-java-component-vcenter-cve-2021-22005-ceip-analytics-agent-jsp-file-write]] 提供 root Webshell 与 data.mdb 读取；log4j2 变体也可写 shell。
- **后续利用**：拿到 vSphere Client 后可生成域控快照并抓 LSASS，见 [[pentest-lateral-movement-vcenter-snapshot-vmss2core-windbg-mimikatz-lsass-hash]]。
- **边界**：Cookie 与 SSO Domain/证书绑定；证书轮换后旧 Cookie/脚本失效；若启用了 MFA/智能卡等额外认证，SAML 伪造可能不足；Cookie 有效期有限。

## 检测与防御

- **保护 `data.mdb`**：严格限制文件权限（仅 vmdir 服务/root），监控异常读取/下载；vCenter 主机一旦被 root 控制，应视为 SSO 凭据已泄露。
- **证书轮换**：发生入侵后轮换 vCenter SSO IdP 证书/信任链，吊销旧会话，重置 `Administrator@vsphere.local` 与域管凭据。
- **检测**：监控 `/websso/SAML2/SSO/` 异常登录、`VSPHERE-UI-JSESSIONID` 的异常签发/复用、非浏览器客户端的 SAML 请求；审计 vCenter 登录日志与 Cookie 使用。
- **网络**：vCenter 管理面不要暴露公网；限制 443 访问来源；对管理流量做双因素/跳板。
- **合规**：仅授权测试；Cookie/证书属于高敏感数据，报告中脱敏。
