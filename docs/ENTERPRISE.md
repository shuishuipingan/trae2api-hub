# Trae Enterprise / SaaS 支持状态

## 结论

当前网关只实现 Trae 国内版和国际版**个人账号**。Trae Enterprise/SaaS 暂未接入，不能通过选国际版、修改 host 或粘贴企业 refreshToken 变成已支持。

本轮针对 [issue #9](https://github.com/shuishuipingan/trae2api-hub/issues/9) 修复的是明确企业凭据被误识别为个人凭据的问题；不是宣称企业版端到端代理已经实现。完整企业支持需求继续保留开放。

## 已修复行为

- 检查官方明确标志：scope/loginScope=saas、非空 saasBootConfig，以及明确 SaaS 响应结构；单独 tenant_id 或普通个人 scope 不足以判断企业。
- JSON/桌面导入在构造、写盘、换取令牌前拒绝明确企业账号。历史账号文件不被改写、不被自动转成个人账号；加载报告不支持并跳过。
- 个人 OAuth 授权页隐藏企业登录；回调 userInfo 只可用于拒绝不支持的类型，不能用作已验证身份。上游返回企业响应也不入库。
- 个人 raw/刷新/管理请求及 SOLO 在携带明确企业元数据时拒绝发送，不回退 CN/INTL 默认主机。
- 错误代码为 unsupported_enterprise_account；消息不回显令牌、租户配置或企业 host。

只提供不透明 token 且没有任何企业元数据时，无法可靠识别其账号类型；不会解码未验签 JWT 来声称身份已验证。不要省略企业元数据尝试绕过这个限制。

## 为什么不能共用个人链路

本机官方客户端 3.6.4 的程序资源（不是用户登录态）中存在独立的 saas/oauthService：

| 项目 | 企业客户端行为 |
|---|---|
| 登录配置 | bootConfig.account.saas；生产控制台 console.enterprise.trae.ai |
| 刷新 | apiHost 下 /cloudide/api/v3/trae/oauth/ExchangeToken；RefreshToken、ClientSecret、UserID；结果从 Data 读取 |
| 用户信息 | GetUserInfo 返回 Data.UserInfo、Data.TenantInfoBase、HostInfo |
| 账号上下文 | scope/loginScope=saas、tenant_id、saas_product_type、roleId、saasBootConfig |
| 数据面 | 根据 saasBootConfig.apiHost（远程场景 remoteApi）选择租户出口，而非固定个人主机 |

静态入口：resources/app/out/main.js 的 saas/oauthService、convertToICubeAccountUserInfo，以及 resources/app/out/vs/code/node/cliProcessMain.js 的 isBusinessUser 分支。上述证据只证明协议分离，不能证明网关对任意企业租户均可用。

## 完整接入仍需完成

1. 独立的租户授权、令牌响应归一化与账号类型存储。
2. 经验证的租户主机选择，严格限制凭据发送目的地，禁止个人主机回退。
3. 租户上下文、企业模型目录、用量/配额、刷新轮换与多协议数据面适配。
4. 使用合成夹具覆盖拒绝/续期/错误隔离后，再完成实际企业账号端到端验收。

## 回归

~~~bash
python -m unittest test_issue_enterprise test_oauth_core test_oauth_http
~~~

所有新增用例使用合成账号与临时目录，不读取个人账号或企业登录态，不访问真实上游。
