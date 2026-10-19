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

RUN mkdir -p /app/accounts /app/usage && \
    (chmod +x /app/start-trae2api-hub.sh /app/start-trae2api-hub-lan.sh \
              /app/allow-firewall.sh 2>/dev/null || true)

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
