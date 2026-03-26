FROM python:3.13-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# add Keboola's default user to correctly create their home dir (used for uv cache)
RUN adduser --uid 1000 --disabled-password keboola

USER 1000:1000

WORKDIR /code/

COPY pyproject.toml .
COPY uv.lock .
COPY packages/ packages/

RUN uv sync --all-groups --frozen

COPY writer/src/ writer/src/
# datadirtest creates dirs inside test fixtures at runtime, so the keboola user needs write access
COPY --chown=1000:1000 tests/ tests/

CMD ["uv", "run", "--no-sync", "python", "-u", "writer/src/writer_component.py"]
