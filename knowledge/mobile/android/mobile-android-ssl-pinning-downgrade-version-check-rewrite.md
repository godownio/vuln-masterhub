---
id: mobile-android-ssl-pinning-downgrade-version-check-rewrite
title: 严格 SSL pinning 下改用旧版 APK 并重写版本检测 API 抓包
type: scenario
domain: mobile
path: mobile/android
technique: ssl-pinning-downgrade-version-rewrite
aliases:
- 旧版本 APK 抓包
- 版本检测重写
- SSL pinning 降级绕过
- Reqable 脚本改包
- 校园 App 抓包
tags:
- android
- ssl-pinning
- downgrade
- version-check
- traffic-interception
- reqable
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:22:17+08:00'
  notes: 已对照原文与10张截图核对：新版严格 pinning/反作弊、改用旧版 APK、Reqable 脚本改写 /run-front/common/update 响应（haveUpdate=false、newVersion/downloadUrl 清空）、旧版与新版签名逻辑一致均与图文相符；已把原理处“newVersion 改为当前版本”修正为“清空或改为当前版本”以匹配截图。未验证点：原文未给出具体脚本与完整抓包过程。
---

## 一句话结论

当新版 App 的 SSL pinning/反作弊过强、难以直接绕过时，可安装旧版本 APK（pinning 较弱），再用抓包工具的脚本能力重写“版本检测/更新”接口响应，让 App 认为已是最新版并继续使用旧协议，从而抓到加密接口与 sign 字段。

## 原理

- SSL pinning 把证书/公钥固定在客户端；新版 App 可能同时加入多开、模拟器、root、hook、调试器、so 注入等检测，直接 Frida/JustTrustMe 容易被反制。
- 旧版本 APK 往往没有同等强度的 pinning/反作弊；但服务端可能通过版本检测接口要求升级，旧版本会被拒绝或功能受限。
- 抓包工具（如 Reqable）支持在代理层用脚本改写响应；把版本检测接口的 `haveUpdate` 改为 `false`，并把 `newVersion`/`downloadUrl` 清空或改为当前版本，即可让旧版 App 通过版本门。
- 旧版与新版的协议/签名逻辑通常保持一致（文章验证旧版 dex 与新版逻辑相同），因此用旧版抓到的接口和算法可用于分析新版。
- 根因是“客户端版本门”可被本地代理改写，而 pinning 只保护传输层、不保护版本判断逻辑。

## 触发条件

- 能获取目标 App 的旧版本 APK（应用商店历史版本、第三方镜像、备份）。
- 服务端有版本检测/更新接口，且客户端信任其响应。
- 旧版本仍能登录/调用核心接口，或版本门可被改写绕过。
- 抓包工具支持脚本化改写响应（Reqable/Fiddler/Charles）。

## 利用步骤

1. 安装旧版 APK，配置代理与系统证书，确认能否抓到明文/密文请求。
2. 找到版本检测接口（如 `/run-front/common/update`），记录请求参数与响应字段。
3. 在抓包工具中写脚本：匹配该接口，把 `haveUpdate` 改为 `false`，`newVersion`/`downloadUrl` 清空或改为当前版本。
4. 重新启动 App，确认不再弹更新/不被拒绝。
5. 抓取核心接口，记录加密响应与 `sign` 请求头，进入逆向签名/加解密阶段。

## PoC

```json
// 版本检测响应改写示例
{
  "code": 0,
  "message": "成功",
  "data": {
    "newVersion": "",
    "downloadUrl": "",
    "updateTitle": "",
    "updateDescription": "",
    "haveUpdate": false,
    "supportVersion": ""
  }
}
```

```python
# Reqable/Fiddler 脚本伪代码
def on_response(request, response):
    if "/run-front/common/update" in request.url:
        body = json.loads(response.body)
        body["data"]["haveUpdate"] = False
        body["data"]["newVersion"] = ""
        response.body = json.dumps(body)
```

## 变体与关联

- 用 Frida hook 版本检测函数/更新对话框，直接返回“无更新”。
- 修改 APK 的版本号/版本检测逻辑后重打包（需过签名校验）。
- 若旧版 pinning 仍强，可尝试 Frida 绕过（见关联卡）。
- 关联：[[mobile-android-ssl-pinning-bypass-cert-frida]]（证书 pinning 绕过）、[[mobile-android-packer-apkid-frida-dexdump-jadx]]（脱壳与 dex dump）。

## 检测与防御

- 服务端强制最低版本，旧版本直接拒绝；版本判断不要只依赖客户端。
- 所有版本都启用证书 pinning，并对代理/重打包/多开做完整性检测。
- 检测：版本检测响应被篡改、旧版本 UA/版本号频繁访问、代理证书异常。
