# 开放 Issues 修复记录

本轮针对仓库 #2、#4、#5、#6 的修复纳入 v1.5.1 发布。下文记录离线验收结果与部署语义；远端发布、CI 和镜像状态以 GitHub Actions / Release 的实时记录为准。

## 修复对照

| Issue | 本地修复 |
| --- | --- |
| #2 OAuth 添加账号崩溃 | 不再读取不存在的 state；不支持的设备授权返回 HTTP 501 结构化 JSON；添加账号主入口使用桌面扫描、JSON 或 refreshToken，不再轮询不可用授权流程。 |
| #4 shell 执行权限 | 5 个受版本控制的 .sh 在 Git 索引中统一为 100755；保留 LF；Docker 对全部根目录 .sh 补执行位，新增运行资源完整性检查。 |
| #5 导入断连、macOS 扫描为空、扫描结果不显示 | 桌面路径解析支持 Windows/macOS/Linux；保留 APPDATA 注入；显式 path 仅导入指定文件；扫描结果提供 valid/path/kind 等前端字段；桌面导入统一 dict 报告；JSON 导入消费整数计数/errors，不再对整数调用 len。 |
| #6 用量、上下文与运行参数 | usage 缺失仍记录请求且标注未知；补齐 SOLO 成功/失败记账；缓存未知不伪造 0% 命中；统计路径统一；上下文保存/读取/清除、模型列表回显与本地预算准入生效；补齐模型列表路由别名；每号并发默认 2；后台签到错峰与调度时间抖动可配置。 |

### 账号导入接口

- POST /accounts/login/start：不支持时返回 501 + status=unsupported + error.message。
- POST /accounts/import/pat：接受 refresh_token、refreshToken，以及旧 pat 字段。
- POST /accounts/import：支持 dryRun；实际报告 result 包含 imported/updated/skipped 整数与 errors 列表。
- POST /accounts/import/desktop：空对象只扫描；path 仅导入指定凭证；all=true 导入本机候选。result 统一包含 found/preview/path/accounts/errors/error/imported/updated/skipped；accounts 为本次涉及的脱敏视图。
- 管理 POST 在执行处理前检查 X-Panel-Token。桌面文件导入仅接受网关本机 loopback 请求。

### 上下文设置的真实语义

POST /settings/model-context 接受 model、label、realm；空 label 清除覆盖。GET /settings 和 GET /settings/model-context 回显持久化配置。模型列表提供官方档位标签、选中值及窗口信息。

**这是本地 UTF-8 字节数保守估算的准入预算，不是上游 tokenizer，也不是解锁上游窗口。** 指定预算后，输入消息/工具 JSON 的估算加显式输出 reserve 超限返回 400；不静默截断历史、不伪造上游 context_window 参数。未配置覆盖时保持原有请求行为。允许值不得超过目录中已知官方上限；缺少可校验上限时拒绝新增覆盖。

### 并发与调度

- TRAE_MAX_INFLIGHT：每号默认 2，可显式覆盖；0 保留不限的既有语义。
- 后台签到：TRAE_CHECKIN_INTERVAL_SECONDS=45、TRAE_CHECKIN_JITTER_SECONDS=75，默认等待 45~120 秒；保活/权益刷新不被签到长等待替代。
- 调度窗口：09:00 / 21:00 加 0~25 分钟抖动，TRAE_SCHEDULE_JITTER_SECONDS 可覆盖；未到点窗口持久化，重启不重新掷骰。
- 手动 HTTP 保持显式 gap 的历史短间隔，避免原同步接口因新增数分钟等待而超时。需要手动也错峰时使用 TRAE_MANUAL_CHECKIN_INTERVAL_SECONDS / TRAE_MANUAL_CHECKIN_JITTER_SECONDS；此时请求耗时会相应增长。

## 离线回归（本机 Python 3.13.14 / Node 24.19.0）

| 命令 | 结果 |
| --- | --- |
| python _test_trae.py | 240 PASS / 0 FAIL |
| python -m unittest test_issue_context test_issue_desktop test_issue_scheduling | 84 tests OK（35 + 12 + 37） |
| python test_issue_usage.py | 64 checks / 0 FAIL |
| python test_issue_http.py | 95 PASS / 0 FAIL |
| python test_issue_solo.py | 52 PASS / 0 FAIL |
| python test_issue_packaging.py | 63 PASS / 0 FAIL，5 项 Windows POSIX 执行位检查跳过 |
| node test_issue_dashboard.js | 53 PASS / 0 FAIL |
| git diff --check | 通过 |

HTTP 套件使用随机 loopback 端口、临时账号/用量目录、mock 上游。桌面导入集成测试用临时加密 storage.json 穿过真实解密、导入 helper 和 Handler，不仅读 mock 结果。脚本式测试请分进程执行，勿把 usage/solo 当 unittest 模块混跑，以免模块全局状态串扰。

CI 已增加以上回归，并配置 Python 3.11/3.13/3.14。发布前先推送修复提交并核验 CI，再创建版本标签触发多架构镜像发布。

## 验证边界与部署

- 本机 Docker CLI 存在，但 Docker Desktop Linux Engine 未启动，因此未执行实际镜像构建；容器结论仅为静态资源/权限检查，不宣称构建成功。
- macOS/Linux 路径通过平台夹具测试，尚非实体 macOS/Linux 运行实测。
- 没有使用真实账号向上游发请求；上游连通性、真实配额与 token 计数仍以部署后实测为准。
- 现有 8791 进程未被重启，本地文件修复不会自动热加载到旧进程；重启现有部署后生效。
- 不相关 tools 目录未跟踪文件保留，未清理账号数据。

部署验证命令（在现有部署完成文件同步、重启后运行）：

```bash
python _test_trae.py
python test_issue_http.py
python test_issue_solo.py
docker build -t trae2api-hub:issue-fixes .
docker run --rm trae2api-hub:issue-fixes python _test_trae.py
```

问题修复对照如上；GitHub Release / Actions 记录是远端发布与镜像结果的依据，本文件不以静态文本替代实时发布状态。
