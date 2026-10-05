FROM python:3.12.15-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN python -m pip --isolated install --no-cache-dir --index-url https://pypi.org/simple \
    --require-hashes --only-binary=:all: -r requirements.txt \
    && python -m pip check

# 拷贝代码
COPY . .

# 程序文件保持 root 所有；仅持久化数据目录允许服务账号写入。
RUN groupadd --gid 10001 proxyforge \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
       --shell /usr/sbin/nologin proxyforge \
    && install -d -m 0700 -o 10001 -g 10001 /app/data
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["python", "scripts/container_entrypoint.py"]

# 暴露 8000 端口
EXPOSE 8000

# 订阅 Token 位于查询参数中，禁用访问日志以免凭据写入容器日志。
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
