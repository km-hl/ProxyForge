ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ENV container=docker LANG=C.UTF-8
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus python3 python3-venv ca-certificates sudo \
    && python3 -m venv /opt/controller-test
WORKDIR /workspace/ProxyForge
COPY requirements.txt requirements-dev.txt ./
RUN /opt/controller-test/bin/python -m pip --isolated install \
    --index-url https://pypi.org/simple --require-hashes --only-binary=:all: -r requirements-dev.txt \
    && /opt/controller-test/bin/python -m pip check
COPY . .
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
