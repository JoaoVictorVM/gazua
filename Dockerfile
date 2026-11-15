# Image of the Gazua demo, built from a validated wheel and the dependencies pinned in uv.lock.
# Prepare the context first (see docs/demo.md):
#   uv build --wheel --out-dir dist
#   uv export --frozen --no-dev --no-emit-project --format requirements.txt -o dist/requirements.txt
FROM python:3.14-slim-trixie@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY dist/requirements.txt dist/gazua-*.whl /tmp/dist/

RUN python -m pip install --require-hashes --no-deps -r /tmp/dist/requirements.txt \
    && python -m pip install --no-deps /tmp/dist/gazua-*.whl \
    && rm -rf /tmp/dist \
    && useradd --create-home --uid 10001 --user-group gazua \
    && mkdir /work \
    && chown gazua:gazua /work

USER 10001:10001
WORKDIR /work
VOLUME ["/work"]

ENTRYPOINT ["gazua"]
CMD ["demo", "--no-open", "--output", "/work/gazua-demo"]
