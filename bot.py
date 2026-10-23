"""Telegram-бот: звуковой код сопряжения Yandex Station с Wi-Fi.

Запуск: BOT_TOKEN=... python bot.py
"""
from __future__ import annotations

import asyncio
import logging
import os
import tempfile
import time
import uuid
from collections import defaultdict, deque
from contextlib import suppress
from pathlib import Path
from dataclasses import replace

from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ChatAction, ParseMode
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandStart, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    BotCommand,
    BufferedInputFile,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

from dotenv import load_dotenv

import pairing

load_dotenv()

log = logging.getLogger("quasar-pair-bot")

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ALLOWED_IDS = {
    int(part) for part in os.getenv("ALLOWED_IDS", "").replace(" ", "").split(",") if part
}
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "5"))
DEFAULT_TOKEN = os.getenv("DEFAULT_TOKEN", "").strip()
RATE_WINDOW = 60.0

router = Router()
semaphore = asyncio.Semaphore(4)
rate: dict[int, deque[float]] = defaultdict(deque)
last_params: dict[str, pairing.PairingParams] = {}

# сообщения бота, которые нужно убрать перед следующим ответом
tracked: dict[int, list[int]] = defaultdict(list)

HELP_TEXT = (
    "<b>Сопряжение по звуку</b>\n\n"
    "Бот собирает аудиокод с данными Wi-Fi, колонка принимает его микрофоном.\n\n"
    "<b>Как пользоваться</b>\n"
    "• Отправь одним сообщением: <code>МояСеть:пароль</code>\n"
    "• Или нажми «Пошагово» — спрошу SSID, пароль и тип защиты\n"
    "• Включи максимальную громкость и поднеси телефон вплотную к колонке\n"
    "• Колонка должна быть в режиме сопряжения\n\n"
    "<b>Разбор записи</b>\n"
    "Пришли голосовое, аудио или файл с записью кода — вытащу SSID, пароль и токен.\n"
    "Точнее всего разбирается файл: voice Telegram сжимает.\n\n"
    "<b>Ограничение</b>\n"
    "Свой (сгенерированный) токен подходит только для подключения к Wi-Fi. "
    "Привязка к аккаунту на серверах Яндекса с ним не сработает — там нужен настоящий "
    "xTokenCode из приложения.\n\n"
    "<b>Если voice не приходит</b>\n"
    "В Telegram: Настройки → Конфиденциальность → Голосовые сообщения → Все. "
    "Иначе Telegram не даёт ботам присылать голосовые.\n\n"
    "<b>Команды</b>\n"
    "/pair <code>ssid:пароль</code> — сразу сгенерировать\n"
    "/cancel — сбросить ввод\n"
    "/help — эта справка"
)

START_TEXT = (
    "<b>Сопряжение по звуку</b>\n\n"
    "Соберу голосовое сообщение с кодом Wi-Fi, а колонка поймает его микрофоном.\n\n"
    "Самый быстрый способ — одним сообщением:\n"
    "<code>МояСеть:пароль</code>\n\n"
    "Если удобнее по шагам — жми кнопку ниже."
)

MENU_TEXT = "Что дальше?"


class Pair(StatesGroup):
    ssid = State()
    password = State()
    security = State()


# ---------- клавиатуры ----------
def kb_start() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Пошагово", callback_data="pair:start")],
        [InlineKeyboardButton(text="Как это работает", callback_data="pair:help")],
    ])


def kb_cancel() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Отмена", callback_data="pair:cancel")],
    ])


def kb_password() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Без пароля", callback_data="pair:open")],
        [InlineKeyboardButton(text="Отмена", callback_data="pair:cancel")],
    ])


def kb_security() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="WPA/WPA2", callback_data="sec:wpa"),
            InlineKeyboardButton(text="WEP", callback_data="sec:wep"),
        ],
        [InlineKeyboardButton(text="Открытая сеть", callback_data="pair:open")],
        [InlineKeyboardButton(text="Отмена", callback_data="pair:cancel")],
    ])


def kb_decoded(key: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="Сгенерировать код", callback_data=f"again:{key}"),
            InlineKeyboardButton(text="Удалить", callback_data="del:this"),
        ],
        [InlineKeyboardButton(text="Новый Wi-Fi", callback_data="pair:start")],
    ])


def kb_result(key: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="Ещё код", callback_data=f"again:{key}"),
            InlineKeyboardButton(text="WAV файлом", callback_data=f"wav:{key}"),
        ],
        [InlineKeyboardButton(text="Новый Wi-Fi", callback_data="pair:start")],
    ])


# ---------- утилиты ----------
def check_access(user_id: int) -> bool:
    return not ALLOWED_IDS or user_id in ALLOWED_IDS


def allow_rate(user_id: int) -> bool:
    now = time.monotonic()
    bucket = rate[user_id]
    while bucket and now - bucket[0] > RATE_WINDOW:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT:
        return False
    bucket.append(now)
    return True


def html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


async def drop_tracked(bot: Bot, chat_id: int) -> None:
    for message_id in tracked.pop(chat_id, []):
        with suppress(Exception):
            await bot.delete_message(chat_id, message_id)


def track(chat_id: int, message: Message) -> None:
    tracked[chat_id].append(message.message_id)


async def drop_user_message(message: Message) -> None:
    with suppress(Exception):
        await message.delete()


async def send_card(message: Message, text: str, keyboard: InlineKeyboardMarkup | None = None) -> Message:
    sent = await message.answer(text, reply_markup=keyboard)
    track(message.chat.id, sent)
    return sent


def result_text(params: pairing.PairingParams, rendered: pairing.RenderedPairing,
                auto_token: bool = False) -> str:
    ssid = params.ssid if params.security is not pairing.Security.NONE else "—"
    return (
        "<b>Код готов</b>\n\n"
        f"• Сеть: <code>{html(ssid)}</code>\n"
        f"• Защита: {params.security.label}\n"
        f"• xTokenCode: <code>{html(params.token)}</code>\n"
        f"• Длительность: {rendered.duration:.1f} с\n\n"
        "Включи максимальную громкость и поднеси телефон вплотную к микрофону колонки."
        + (
            "\n\n<b>Важно</b>: токен сгенерирован ботом. Колонка подключится к Wi-Fi, "
            "но привязка к аккаунту на серверах Яндекса не сработает — для неё нужен "
            "настоящий xTokenCode из приложения (выпускается под аккаунт)."
            if auto_token else ""
        )
    )


async def generate_and_send(message: Message, params: pairing.PairingParams, state: FSMContext) -> None:
    # xTokenCode: в приложении это Passport-токен (getXTokenCode), в кадре
    # колонка принимает любое непустое значение. Шлём рандомный на каждую
    # генерацию — пустой токен может отбрасываться при разборе («не расслышала»).
    auto_token = not params.token
    if auto_token:
        params = replace(params, token=pairing.random_token())
    async with semaphore:
        await message.bot.send_chat_action(message.chat.id, ChatAction.RECORD_VOICE)
        rendered = await asyncio.to_thread(pairing.render, params)
        voice = await asyncio.to_thread(rendered.voice)

    key = uuid.uuid4().hex[:8]
    last_params[key] = params
    if len(last_params) > 200:
        last_params.pop(next(iter(last_params)))

    try:
        sent = await message.bot.send_voice(
            chat_id=message.chat.id,
            voice=BufferedInputFile(voice, filename="pairing.ogg"),
            duration=round(rendered.duration),
        )
        track(message.chat.id, sent)
    except TelegramBadRequest as exc:
        if "VOICE_MESSAGES_FORBIDDEN" not in str(exc):
            raise
        await state.clear()
        await send_card(
            message,
            "<b>Telegram не даёт прислать голосовое</b>\n\n"
            "У тебя в настройках приватности запрещены голосовые от ботов.\n"
            "Настройки → Конфиденциальность → Голосовые сообщения → Все.\n\n"
            "Пока можно забрать код файлом:",
            InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="WAV файлом", callback_data=f"wav:{key}")],
            ]),
        )
        log.info("voice forbidden chat=%s", message.chat.id)
        return

    menu = await message.bot.send_message(
        message.chat.id,
        result_text(params, rendered, auto_token),
        reply_markup=kb_result(key),
    )
    track(message.chat.id, menu)
    await state.clear()

    log.info(
        "generated user=%s security=%s symbols=%d duration=%.1f",
        message.from_user.id if message.from_user else "?",
        params.security.name, rendered.symbols, rendered.duration,
    )


def parse_pair_text(text: str) -> pairing.PairingParams | None:
    parts = text.split(":", 2)
    if len(parts) < 2:
        return None
    ssid, password = parts[0].strip(), parts[1].strip()
    token = parts[2].strip() if len(parts) > 2 else DEFAULT_TOKEN
    if not ssid:
        return None
    return pairing.PairingParams(
        ssid=ssid, password=password, security=pairing.Security.WPA, token=token
    )


async def finish(message: Message, state: FSMContext) -> None:
    data = await state.get_data()
    security = pairing.Security(data.get("security", int(pairing.Security.WPA)))
    params = pairing.PairingParams(
        ssid=data.get("ssid", ""),
        password=data.get("password", ""),
        security=security,
        token=DEFAULT_TOKEN,
    )
    try:
        await generate_and_send(message, params, state)
    except pairing.PairingError as exc:
        await state.clear()
        await send_card(message, f"Не получилось: {html(str(exc))}", kb_start())
    except Exception:
        log.exception("generation failed")
        await state.clear()
        await send_card(message, "Сбой генерации. Попробуй ещё раз.", kb_start())


# ---------- хендлеры ----------
@router.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext) -> None:
    if not check_access(message.from_user.id):
        return
    await state.clear()
    await send_card(message, START_TEXT, kb_start())


@router.message(Command("help"))
async def cmd_help(message: Message) -> None:
    if not check_access(message.from_user.id):
        return
    await send_card(message, HELP_TEXT, kb_start())


@router.message(Command("cancel"))
async def cmd_cancel(message: Message, state: FSMContext) -> None:
    if not check_access(message.from_user.id):
        return
    await state.clear()
    await send_card(message, "Сбросил. Пришли <code>SSID:пароль</code>.", kb_start())


@router.message(Command("pair"))
async def cmd_pair(message: Message, state: FSMContext) -> None:
    if not check_access(message.from_user.id):
        await drop_user_message(message)
        return
    text = (message.text or "").partition(" ")[2].strip()
    if not allow_rate(message.from_user.id):
        await send_card(message, "Слишком часто. Подожди минуту.")
        return
    params = parse_pair_text(text)
    if params is None:
        await send_card(message, "Формат: <code>/pair МояСеть:пароль</code>", kb_start())
        return
    await drop_user_message(message)  # в команде были учётные данные
    try:
        await generate_and_send(message, params, state)
    except pairing.PairingError as exc:
        await send_card(message, f"Не получилось: {html(str(exc))}", kb_start())


@router.callback_query(F.data == "pair:help")
async def cb_help(call: CallbackQuery) -> None:
    await call.message.edit_text(HELP_TEXT, reply_markup=kb_start())
    await call.answer()


@router.callback_query(F.data == "pair:cancel")
async def cb_cancel(call: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await call.message.edit_text(START_TEXT, reply_markup=kb_start())
    await call.answer("Отменено")


@router.callback_query(F.data == "pair:start")
async def cb_start(call: CallbackQuery, state: FSMContext) -> None:
    if not allow_rate(call.from_user.id):
        await call.answer("Слишком часто. Подожди минуту.", show_alert=True)
        return
    await state.set_state(Pair.ssid)
    await call.message.edit_text(
        "<b>Шаг 1 из 3</b>\n\nПришли название сети (SSID) — точно как в списке Wi-Fi.",
        reply_markup=kb_cancel(),
    )
    await call.answer()


@router.message(Pair.ssid)
async def step_ssid(message: Message, state: FSMContext) -> None:
    await drop_user_message(message)
    ssid = (message.text or "").strip()
    if not ssid:
        await send_card(message, "Нужен текст — имя Wi-Fi сети.", kb_cancel())
        return
    if len(ssid.encode()) > pairing.SSID_MAX:
        await send_card(message, f"SSID длиннее {pairing.SSID_MAX} байт — так не бывает.", kb_cancel())
        return
    await state.update_data(ssid=ssid)
    await state.set_state(Pair.password)
    await send_card(
        message,
        "<b>Шаг 2 из 3</b>\n\nПришли пароль от Wi-Fi.\n"
        "Если сеть открытая — нажми «Без пароля».",
        kb_password(),
    )


@router.message(Pair.password)
async def step_password(message: Message, state: FSMContext) -> None:
    await drop_user_message(message)
    if not message.text:
        await send_card(message, "Пришли пароль текстом или нажми «Без пароля».", kb_password())
        return
    password = message.text.strip()
    if len(password.encode()) > pairing.PASSWORD_MAX:
        await send_card(message, f"Пароль длиннее {pairing.PASSWORD_MAX} байт — проверь раскладку.",
                        kb_password())
        return
    await state.update_data(password=password)
    await state.set_state(Pair.security)
    await send_card(message, "<b>Шаг 3 из 3</b>\n\nТип защиты сети:", kb_security())


@router.callback_query(Pair.security, F.data.in_({"sec:wpa", "sec:wep"}))
async def step_security(call: CallbackQuery, state: FSMContext) -> None:
    security = pairing.Security.WPA if call.data == "sec:wpa" else pairing.Security.WEP
    await state.update_data(security=int(security))
    await call.message.edit_text("<b>Генерирую код…</b>")
    await finish(call.message, state)
    await call.answer()


@router.callback_query(F.data == "pair:open")
async def step_open(call: CallbackQuery, state: FSMContext) -> None:
    data = await state.get_data()
    if "ssid" not in data:
        await call.answer("Сначала пришли SSID", show_alert=True)
        return
    await state.update_data(security=int(pairing.Security.OPEN), password="")
    await call.message.edit_text("<b>Генерирую код…</b>")
    await finish(call.message, state)
    await call.answer()


@router.callback_query(F.data == "del:this")
async def cb_delete(call: CallbackQuery) -> None:
    with suppress(Exception):
        await call.message.delete()
    await call.answer("Удалено")


@router.callback_query(F.data.startswith("again:"))
async def cb_again(call: CallbackQuery, state: FSMContext) -> None:
    params = last_params.get(call.data.split(":", 1)[1])
    if params is None:
        await call.answer("Код устарел, сгенерируй заново", show_alert=True)
        return
    await call.answer()
    try:
        await generate_and_send(call.message, params, state)
    except Exception:
        log.exception("regeneration failed")


@router.callback_query(F.data.startswith("wav:"))
async def cb_wav(call: CallbackQuery) -> None:
    params = last_params.get(call.data.split(":", 1)[1])
    if params is None:
        await call.answer("Код устарел, сгенерируй заново", show_alert=True)
        return
    await call.answer()
    rendered = await asyncio.to_thread(pairing.render, params)
    sent = await call.message.answer_document(
        BufferedInputFile(rendered.wav(), filename="pairing.wav"),
        caption="Тот же код без сжатия.",
    )
    track(call.message.chat.id, sent)



@router.message(F.voice | F.audio | F.document)
async def decode_incoming(message: Message, state: FSMContext) -> None:
    if not check_access(message.from_user.id):
        await drop_user_message(message)
        return
    media = message.voice or message.audio or message.document
    if media is None:
        return
    if (media.file_size or 0) > 10 * 1024 * 1024:
        await drop_user_message(message)
        await send_card(message, "Файл больше 10 МБ — пришли короткую запись.", kb_start())
        return
    file_id = media.file_id
    await drop_user_message(message)
    await message.bot.send_chat_action(message.chat.id, ChatAction.TYPING)

    suffix = ".ogg" if (message.voice or getattr(media, "mime_type", "") in ("audio/ogg", "audio/opus")) else ".bin"
    with tempfile.TemporaryDirectory(prefix="quasar-bot-") as tmp:
        path = Path(tmp) / ("input" + suffix)
        try:
            await message.bot.download(file_id, destination=path)
        except Exception:
            log.exception("download failed")
            await send_card(message, "Не смог скачать файл.", kb_start())
            return
        try:
            decoded = await asyncio.to_thread(pairing.decode_recording, path)
        except pairing.PairingError as exc:
            await send_card(
                message,
                f"<b>Не разобрал</b>\n\n{html(str(exc))}\n\n"
                "Лучше присылать файлом (не голосовым): Telegram сжимает voice и портит хвост кадра.",
                kb_start(),
            )
            return
        except Exception:
            log.exception("decode failed")
            await send_card(message, "Сбой разбора записи.", kb_start())
            return

    key = uuid.uuid4().hex[:8]
    last_params[key] = decoded.params
    token_line = f"<code>{html(decoded.params.token)}</code>" if decoded.params.token else "нет"
    kinds = {"wifi": "Wi-Fi конфиг", "auth": "только авторизация (authCode)",
             "intro": "вступление", "unknown": "неизвестный"}
    text = (
        "<b>Разобрал запись</b>\n\n"
        f"• Тип кадра: {kinds.get(decoded.kind, decoded.kind)}\n"
        f"• Сеть: <code>{html(decoded.params.ssid or '—')}</code>\n"
        f"• Пароль: <code>{html(decoded.params.password or '—')}</code>\n"
        f"• Защита: {decoded.params.security.label}\n"
        f"• Токен: {token_line}\n"
        f"• CRC: {'ок' if decoded.crc_ok else 'не сошёлся'}, исправлено символов: {decoded.errors}\n"
        f"• Символов в кадре: {decoded.symbols}\n"
        f"• Payload: <code>{decoded.payload.hex()}</code>"
    )
    await send_card(message, text, kb_decoded(key))
    log.info("decoded user=%s kind=%s crc=%s errors=%d", message.chat.id,
             decoded.kind, decoded.crc_ok, decoded.errors)


@router.message(StateFilter(None))
async def direct_pair(message: Message, state: FSMContext) -> None:
    if not check_access(message.from_user.id):
        await drop_user_message(message)
        return
    if not message.text:
        await drop_user_message(message)
        await send_card(message, "Пришли текст: <code>SSID:пароль</code>", kb_start())
        return
    params = parse_pair_text(message.text)
    await drop_user_message(message)
    if params is None:
        await send_card(message, "Не понял. Пришли <code>МояСеть:пароль</code>.", kb_start())
        return
    if not allow_rate(message.from_user.id):
        await send_card(message, "Слишком часто. Подожди минуту.")
        return
    try:
        await generate_and_send(message, params, state)
    except pairing.PairingError as exc:
        await send_card(message, f"Не получилось: {html(str(exc))}", kb_start())


async def on_startup(bot: Bot) -> None:
    await bot.set_my_commands([
        BotCommand(command="start", description="Начать"),
        BotCommand(command="pair", description="Код по ssid:пароль"),
        BotCommand(command="cancel", description="Отмена"),
        BotCommand(command="help", description="Справка"),
    ])
    me = await bot.get_me()
    log.info("bot started as @%s", me.username)


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN не задан (см. .env.example)")

    bot = Bot(BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher(storage=MemoryStorage())
    dp.include_router(router)
    dp.startup.register(on_startup)
    await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())


if __name__ == "__main__":
    asyncio.run(main())
