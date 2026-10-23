# quasar-connect-bot

Telegram-бот, который собирает **звуковой код сопряжения Yandex Station с Wi-Fi** и присылает его голосовым сообщением. Колонка принимает код микрофоном — телефон просто проигрывает звук рядом.

Протокол восстановлен из приложения `com.yandex.iot` («Умный Дом», 26.18.0): `playPairingSound` → `PairingSoundController` → `fx1.a` → `dx1.d`.

## Возможности

- `SSID:пароль` или `SSID:пароль:токен` одним сообщением
- пошаговый ввод: SSID → пароль → тип защиты (WPA/WEP/открытая)
- голосовое сообщение (OGG/Opus 48 кГц) + кнопка «WAV файлом»
- разбор присланной записи: voice, аудио или видео → SSID, пароль, тип, токен
- удаление сообщений с учётными данными, команды и ответы бота не трогаются
- рейт-лимит и опциональный allowlist по user ID

## Формат кадра

- 16 кГц, моно, PCM16, полная шкала; символ = 640 сэмплов = 40 мс
- частота символа: `f = 1024 + 256 * nibble`, 4 бита на символ
- кадр: `6192, 6192, 5120, 5120` → `1024, 1024` → данные → `5632 × 8`
- payload: `u8 тип-1` → SSID (для открытой сети — `int16 LE` от `java_hash % 32767`) → `u8 len + пароль` → `u8 len + xTokenCode` → `u16 CRC32 & 0xFFFF` **little-endian**
- помехоустойчивость: нибблы по 11 в блок + 4 проверочных = RS(15,11) над GF(16), полином `0x13`, generator base 1

Длины: пустой токен — 58 символов / 2.32 с, токен 16 символов — 102 / 4.08 с, 43 символа — 176 / 7.04 с.

## Запуск

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env    # вписать BOT_TOKEN
.venv/bin/python bot.py
```

Нужен `ffmpeg` в `PATH` — им собирается OGG/Opus и разбираются записи.

## Переменные окружения

- `BOT_TOKEN` — токен от [@BotFather](https://t.me/BotFather), обязателен
- `ALLOWED_IDS` — необязательно, ID пользователей через запятую
- `RATE_LIMIT` — генераций на пользователя в минуту, по умолчанию 5

## Деплой (pm2)

```bash
rsync -az --exclude .venv --exclude .env --exclude __pycache__ ./ user@host:~/quasar-connect-bot/
ssh user@host 'cd ~/quasar-connect-bot && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt'
ssh user@host 'cd ~/quasar-connect-bot && printf "BOT_TOKEN=...\n" > .env && chmod 600 .env'
ssh user@host 'cd ~/quasar-connect-bot && pm2 start .venv/bin/python --name quasar-connect-bot -- bot.py && pm2 save'
```


## Тесты

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Покрыто: payload (WPA/open/none, CRC, unicode), RS-синдромы, структура кадра, round-trip синтез → демодуляция → payload, WAV, выживание после Opus, разбор собственного голосового.

## Ограничения

- Сгенерированный ботом токен подходит только для подключения к Wi-Fi. Привязка к аккаунту на серверах Яндекса с ним не сработает: настоящий `xTokenCode` выпускает Паспорт под конкретный аккаунт (`/1/bundle/auth/x_token/`, заголовок `Ya-Consumer-Authorization: OAuth ...`), офлайн его не получить.
- Пароль с двоеточием в формате `ssid:pass` сломает разбор — используйте пошаговый ввод.
- Запись для разбора лучше присылать файлом: голосовые Telegram пережимает и портят хвост кадра.

## Лицензия

MIT
