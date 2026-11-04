FROM python:3.12-slim

ARG TOY_VERSION=0.1.0
ENV TOY_VERSION=${TOY_VERSION}
ENV PYTHONDONTWRITEBYTECODE=1

RUN useradd -m toy
WORKDIR /app
COPY app.py /app/app.py
USER toy

EXPOSE 4000
CMD ["python", "app.py"]
