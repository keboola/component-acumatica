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

COPY writer/src/ src/
COPY tests/ tests/
COPY scripts/ scripts/
COPY deploy.sh .

CMD ["uv", "run", "--no-sync", "python", "-u", "src/writer_component.py"]
