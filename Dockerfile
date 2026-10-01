# ObscuraLens container image
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install the package with the optional web extra so `obscuralens serve` works.
COPY pyproject.toml README.md LICENSE ./
COPY obscuralens ./obscuralens
RUN pip install ".[web]"

# Run as an unprivileged user; state lives in a volume.
RUN useradd --create-home --uid 10001 obscuralens \
    && mkdir -p /data \
    && chown obscuralens:obscuralens /data
USER obscuralens

ENV OBSCURALENS_SQLITE_PATH=/data/obscuralens.db \
    OBSCURALENS_CACHE_PATH=/data/http_cache.db \
    OBSCURALENS_CONFIG_DIR=/home/obscuralens/.config/obscuralens \
    OBSCURALENS_NO_COLOR=1

VOLUME ["/data"]
EXPOSE 8000

ENTRYPOINT ["obscuralens"]
CMD ["--help"]
