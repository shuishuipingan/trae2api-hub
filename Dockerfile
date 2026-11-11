# syntax=docker/dockerfile:1
# ===========================================================================
# Trae2API-Hub —— Trae 双区（国内版 CN / 国际版 INTL）OpenAI 兼容反代
#
# 零 pip 依赖：协议、SSE 解析、AES/凭证解密全部为 Python 标准库实现
# （协议事实源见 .team/PROTOCOL.md）。镜像里也带上自检脚本，便于容器内排障：
#   docker run --rm trae2api-hub:latest python _test_trae.py
#   docker run --rm trae2api-hub:latest python _diag_gateway.py --help
# ===========================================================================
FROM python:3.11-alpine

# PORT 是默认端口；HOST 监听全部网卡（容器内必须 0.0.0.0）。
# API_KEY 只作为 compose / docker run -e 的覆盖入口，默认空：
# 容器以 --lan 启动，首次会生成随机 Key 并写入 /app/accounts/settings.json。
ENV PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8791 \
    API_KEY= \
    TZ=Asia/Shanghai

WORKDIR /app

RUN apk add --no-cache tzdata ca-certificates && \
    cp /usr/share/zoneinfo/${TZ} /etc/localtime && \
    echo "${TZ}" > /etc/timezone

# 整目录拷贝（.dockerignore 已排除 .git/.team/.recon/accounts/usage 等）。
# 不逐个列举文件名：数据面/目录/账号模块都在并行演进，逐名 COPY 会因为
# 新增或改名直接构建失败。
COPY . /app/

# issue4：镜像内脚本执行位。git 索引已统一 100755，但本地 Windows 构建、
# 旧快照或 zip 解包常见 644 —— 这里按通配补齐**全部** .sh（含兼容层），
# 不再硬编码文件名（漏一个就是镜像里一个不可执行的启动脚本）。
RUN chmod +x /app/*.sh 2>/dev/null || true

RUN mkdir -p /app/accounts /app/usage

# issue4 发布面自检：新增的资源目录（i18n / pricing / 前端静态资源 / 目录快照）
# 一旦被 .dockerignore 误排除，构建阶段直接失败，而不是等运行时才 404。
RUN python -c "import os,sys; req=['trae_proxy.py','trae_client.py','trae_catalog.py','trae_accounts.py','trae_oauth.py','dashboard.html','dashboard-v3.css','dashboard-v3.js','dashboard-charts.js','i18n/en.json','pricing/trae_pricing.json','trae_catalog_cn.json','trae_catalog_intl.json']; miss=[p for p in req if not os.path.isfile(os.path.join('/app',p))]; print('[packaging] missing: %s' % miss if miss else '[packaging] assets ok'); sys.exit(1 if miss else 0)"

# 凭证与用量必须挂卷，否则重建容器就丢账号、丢流水
VOLUME ["/app/accounts", "/app/usage"]

EXPOSE 8791

# 健康探针：/ping 永远 200、不查账号池、不需要 Key；URL 跟随 PORT，
# 重映射端口后仍然正确。
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/ping' % os.environ.get('PORT','8791'), timeout=3)" || exit 1

# --lan：监听全部网卡并强制生成随机 Key（首启写入 /app/accounts/settings.json
# 并在日志打印一次）。显式 -e API_KEY=... 时以环境变量为准。
# 需要附加参数（--accounts-dir 等）时用 compose 的 command: 覆盖本 CMD。
CMD ["python", "trae_proxy.py", "--lan"]
