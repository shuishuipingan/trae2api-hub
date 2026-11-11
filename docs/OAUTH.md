# 浏览器 OAuth 登录

## 使用

1. 启动更新后的网关，登录管理面板，打开「添加账号」。
2. 在「浏览器 OAuth 登录」选择国内版或国际版，点击「开始浏览器授权」。
3. 浏览器打开对应官方授权页，完成登录与授权。被浏览器拦截弹窗时，点击「打开授权页」。
4. 浏览器和网关在同一台机器时，官方页面回跳到 `http://127.0.0.1:<随机端口>/authorize`；面板查询到成功后刷新账号列表。
5. 浏览器与网关不在同机，或网关运行在容器中时，浏览器的 localhost 不是网关的 localhost。展开「浏览器不在网关机器？粘贴回调地址」，将授权完成后地址栏中的完整回调 URL 粘贴并提交。不要重新开始另一场授权再粘贴上一场回调。
6. 不再使用时点击取消或关闭窗口；会话十分钟到期。失败后重新发起，旧回调不能重复使用。

这是浏览器授权码流程，不是 device-code flow；没有用户码或设备码。桌面凭证扫描、JSON 导入和 refreshToken 导入继续可用。OAuth 私钥随账号文件原子保存；后续请求与刷新保留相同设备身份。

## 接口

以下管理接口均使用有效的 `X-Panel-Token` 面板会话，而不是模型 API Key。

| 方法 | 路径 | 请求/结果 |
|---|---|---|
| POST | /accounts/login/start | {"realm":"cn"} 或 {"realm":"intl"}；返回 state、authorization_url、redirect_uri、expires_at、interval |
| GET | /accounts/login/poll?state=STATE | pending / exchanging / success / failed / expired / cancelled / not_found；不返回令牌、verifier 或私钥 |
| POST | /accounts/login/cancel | {"state":"STATE"}；返回 cancelled |
| POST | /accounts/login/callback | {"state":"STATE","callback_url":"完整回调 URL"}；只接受当前会话的回环地址、端口、路径及 trace |

本机回调由独立、仅绑定 127.0.0.1 的监听器处理，无须面板 header；单次 trace/PKCE 会话负责关联。管理端手动回调仍需面板会话。不能用另一个面板会话查询、取消或提交已有会话。

## 协议依据与验证边界

国际版官方桌面客户端静态代码证据：版本 1.107.1、tronBuildVersion 2.3.93439；产品配置中 stable IDE client_id 为 ono9krqynydwx5。授权 URL 使用 /authorization、login_channel=native_ide、auth_callback_url、login_trace_id、code_challenge 和 S256。授权码来自 authCodeInfo JSON 的 AuthCode，verifier 留在本地。

交换接口为官方账号主机下 /trae/api/v3/oauth/ExchangeToken，请求体 ClientID、AuthCode、CodeVerifier、DeviceInfo（P-256 SPKI 公钥）与 IDEVersion；x-cloudide-token 为空。无可信 UID 时通过带令牌的 /cloudide/api/v3/trae/GetUserInfo 获取；不信任回调 query 的 userInfo UID，也不把未验签 JWT 解析当身份验证。

公开实现交叉参照：

- [TraeWorkAssistant 固定源码快照](https://github.com/smart-open/TraeWorkAssistant/blob/a50d65f7a2f0d3dd3b0b8ae4179199276bd93466/src-tauri/src/commands/oauth.rs)
- [magpie 固定源码快照](https://github.com/magpie-community/plugins/blob/a69931eccb7a2f98ef6cdbd21cf88d9568392a0d/packages/trae/index.mjs)
- [cockpit OAuth 实现](https://github.com/jlcodes99/cockpit-tools/blob/main/crates/cockpit-core/src/modules/trae_oauth.rs)

国内版授权域来自现有项目与公开实现交叉证据，本机没有国内版官方 product.json。严格要求回调携带当前 loginTraceID/login_trace_id/state；官方客户端静态代码没有证明所有地区均回显 trace，部分公开抓包实现声明会回显。未带 trace 的回调会明确失败，而不会猜测或绑定到最近会话。

本次验证是临时目录、mock 令牌交换和真实回环 HTTP 的隔离集成测试，不是使用真实账号完成官方授权；CN/INTL/企业分支的上游实际登录结果仍以用户操作为准。没有改变已有 refresh 协议为未经验证的新变体。

## 回归

~~~bash
python -m unittest test_oauth_core test_oauth_http
node test_oauth_dashboard.js
node test_issue_dashboard.js
python test_issue_http.py
~~~

全流程不读取操作系统凭证库或真实账号文件；单元测试 fake transport 不访问上游。
