FROM python:3.12.15-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN python -m pip --isolated install --no-cache-dir --index-url https://pypi.org/simple \
    --require-hashes --only-binary=:all: -r requirements.txt \
    && python -m pip check

# 拷贝代码
COPY . .

# 暴露 8000 端口
EXPOSE 8000

# 订阅 Token 位于查询参数中，禁用访问日志以免凭据写入容器日志。
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
