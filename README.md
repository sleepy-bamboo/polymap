# Polymap

Инструмент для сбора IAM/S3 и визуализации графа доступов.

## Установка

Вариант 1: локально, через виртуальное окружение.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e .
```

Вариант 2: в уже существующее окружение.

```bash
python -m pip install -e .
```

Проверка, что CLI доступна:

```bash
polymap --help
```

## Быстрый старт

1) Собрать данные из AWS и построить граф:

```bash
polymap scan --profile default --region us-east-1 --out-dir ./out
```

2) Открыть веб‑интерфейс:

```bash
polymap serve --out-dir ./out --host 127.0.0.1 --port 8080
```

Откройте в браузере `http://127.0.0.1:8080`.

## Команды

### scan

```bash
polymap scan --profile PROFILE --region REGION --out-dir ./out
```

Опции:
- `--profile` — AWS profile из `~/.aws/credentials`
- `--region` — регион (IAM глобальный, S3 почти глобальный)
- `--out-dir` — папка с результатами
- `--strict-ambiguous` — сохранять `AMBIGUOUS`, не заменяя на `DENIED`

### serve

```bash
polymap serve --out-dir ./out --host 127.0.0.1 --port 8082
```

## Локальные сценарии (без AWS)
Где сценарий - набор настроек конфигурации хранилища в json
```bash
python test/run_scenario.py --scenario <NUMBER> # номер сценария (1–4)
```

Строгий режим для неоднозначных условий:

```bash
python test/run_scenario.py --scenario <NUMBER> --strict-ambiguous
```

## Что внутри `out`:

- `iam.json` — выгрузка IAM
- `s3.json` — выгрузка S3
- `analysis.json` — анализ доступов
- `graph.json` — граф для визуализации
- `report.json` — ранжирование путей

## Примечания

- В строгом режиме `AMBIGUOUS` остаётся `AMBIGUOUS`.
- В обычном режиме `AMBIGUOUS` трактуется как `DENIED` до полной поддержки условий.

