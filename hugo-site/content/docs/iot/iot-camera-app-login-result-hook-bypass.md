---
id: iot-camera-app-login-result-hook-bypass
title: 摄像头 APP 登录结果 Hook 绕过：Frida 篡改 LoginDev result=0 无密码拉取实时视频流
type: scenario
domain: iot
path: iot
technique: camera-app-login-result-hook-bypass
tags:
- iot
- camera
- android
- frida
- hook
- auth-bypass
- p2p
- ppcs
- video-stream
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V341
  verified_at: '2026-11-08T20:45:35+08:00'
  notes: 已对照原文及13张图核对：LoginDev result=0/-1、LuPPCSSession.sendUserData Hook 的类名/重载/result 覆写与文章截图一致；未在真机复跑
url: /docs/iot/iot-camera-app-login-result-hook-bypass/
draft: false
kb_aliases:
- LoginDev result 篡改
- 摄像头客户端鉴权绕过
- LuPPCSSession.sendUserData Hook
- LookCam 免密连接
- PPCS P2P 无密码拉流
---

## 一句话结论

摄像头把「登录是否成功」的判定交给 APP：APP 发送 `LoginDev` 后只检查响应里的 `result`（0 成功、-1 口令错误），并据此更新设备状态；用 Frida Hook `com.view.ppcs.DataCenter.LuPPCSSession.sendUserData`，把 `cmd=LoginDev` 的响应 `result` 改成 0，APP 即进入已登录状态，仅凭设备码就能连接并拉取实时视频流——说明设备端没有把服务端会话作为后续指令的硬门禁。

## 原理

- 控制通道：APP 与摄像头走 UDP P2P（自定义 PPCS 协议），指令是 JSON 键值，每条指令都会带 `pwd` 字段；`LoginDev` 用于登录，响应中 `result=0` 表示成功、`-1` 表示密码错误（反编译代码里还处理 `-2` 分支）。
- APP 侧关键逻辑：反编译后 `loginDevice()` 组装 `{"cmd":"LoginDev","pwd":<this.mPwd>}`，调用 `sendUserData` 同步收取响应并读取 `result`；成功时置 `isLoggedIn=true`、`hasPwd=true` 并 `updateState(1)`，失败按 `-1/-2` 置 state 2/4。后续连接、播放、指令按钮都依赖这个状态机。
- 为什么能绕过：设备虽然对错误的 `LoginDev` 返回 -1，但并不把这个失败结果变成设备侧强制拒绝状态——文中实测，把 APP 判定改成成功后，后续 `GetDevStream` 仍被设备执行并返回视频流。真正的准入拦截发生在 APP 内部，所以篡改 APP 的判定/返回值就能跨过口令。
- Hook 点选择：`sendUserData(JSONObject, boolean)` 是请求-响应封装，原函数负责把登录 JSON 发给设备并拿到响应对象；Hook 在原函数返回后、`loginDevice()` 读取之前，把响应 JSONObject 的 `result` 覆写为 0。这样既不需要知道口令，也不用改设备端。
- 前提是攻击者能用 Frida 注入 APP（root、可调试包或重打包），并且知道设备码/序列号用于 P2P 寻址；不需要设备口令。

## 触发条件

- 目标摄像头使用 PPCS/libPPCS_API.so 一类 P2P SDK，配套 APP（LookCam 类）以 `LoginDev` 的 `result` 作为登录判定。
- APP 可被动态插桩：设备已 root、APP 可调试，或攻击者重打包/改包。
- 攻击者掌握设备码/序列号（P2P 寻址与连接需要），但不知道设备密码。
- 设备端未在登录失败后拒绝后续指令，或未对每条指令校验会话/口令（本次实测成立）。

## 利用步骤

1. 用 jadx 反编译 APK，搜索 `LoginDev`/`LoginDevice`，定位 `LuPPCSSession.sendUserData` 以及设备状态更新（`isLoggedIn`、`updateState`）逻辑。
2. 在测试机部署 frida-server（或对可调试包直接 attach），确认能枚举到 `com.view.ppcs.DataCenter.LuPPCSSession`。
3. 加载 Hook 脚本，重写 `sendUserData` 的 `(org.json.JSONObject, boolean)` 重载：先调用原函数拿到响应，再判断请求的 `cmd` 是否为 `LoginDev`，是则 `result.put("result", 0)`。
4. 在 APP 里只输入设备码/序列号发起连接；观察 APP 设备状态变为已登录（state=1），连接后返回实时视频流。
5. 连接成功后，可继续调用 APP 内其他指令（云台、回放、下载等）验证权限范围；仅做只读验证，避免影响设备。

## PoC

Frida Hook（概念，最小化）：

```javascript
Java.perform(function () {
  var S = Java.use("com.view.ppcs.DataCenter.LuPPCSSession");
  S.sendUserData.overload('org.json.JSONObject', 'boolean').implementation = function (req, z) {
    var resp = this.sendUserData(req, z);          // 原逻辑：发包并拿响应
    if (req.get("cmd").equals("LoginDev")) {       // 登录响应
      resp.put("result", 0);                        // 把失败改成成功
    }
    return resp;
  };
});
```

说明：文中实测只需 Hook 这一处即可进入已登录态并拉流；若目标 APP 混淆了类名，可按 `LoginDev` 字符串交叉引用定位发送/判定函数，或改为 Hook 状态更新函数。

## 变体与关联

- 变体：不注入进程而做流量中间人，把设备返回的 `{"result":-1,...}` 改成 `"result":0` 再转给 APP，效果相同（需要能截获/伪造 P2P UDP 会话）。
- 变体：直接改包重打包，修改 `loginDevice()` 中的状态赋值或把结果判断短路；也可 Hook `LuDeviceStateCenter.updateState` 强制 state=1。
- 变体：若 APP 还校验 `hasPwd`/`isLoggedIn` 字段，可一并改写；若设备端另有会话 token，则只能进 UI 不能拉流，需转而攻击会话建立。
- 关联：[[iot-protocol-ppcs-p2p-plaintext-udp-json-simulator]]（同一 P2P 协议的逆向与模拟）、[[iot-protocol-camera-downloadfile-arbitrary-file-read-mtd-mount]]（登录后任意文件下载）、[[iot-camera-wifi-psk-shell-injection-jffs2-persistence]]（同设备升级到 root）。
- 边界：设备对每条指令独立校验口令/会话，或登录失败后服务端封锁会话时，本卡不成立。

## 检测与防御

- 防御：设备端必须自己维护认证状态并作为唯一事实来源——`LoginDev` 失败后拒绝一切业务指令与取流；后续指令校验服务端会话/令牌，而不是信任客户端状态。
- 防御：控制通道加加密与消息认证，禁止明文 `pwd`；对登录失败次数做限制与告警。
- 检测：APP 侧出现 Frida 注入痕迹（frida-server、命名管道、异常线程/端口）或 APK 重签名；设备侧出现 `LoginDev` 失败后紧随 `GetDevStream` 的异常会话。
- 加固：APP 完整性校验/加固只能提高门槛，根因修复必须在设备端。
