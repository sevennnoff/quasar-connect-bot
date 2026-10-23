"""Протокол звукового сопряжения Yandex Station.

Портировано из com.yandex.iot 26.18.0 (классы fx1.a, dx1.b, ex1.a).
Кадр: handshake -> version -> RS-блоки -> handshake end.
"""
from __future__ import annotations

import io
import math
import secrets
import secrets
import string
import struct
import subprocess
import tempfile
import wave
import zlib
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path

SAMPLE_RATE = 16000
SYMBOL_SAMPLES = 640          # 40 мс
BASE_FREQ = 1024              # okio Segment.SHARE_MINIMUM, вшит в dx1.b
FREQ_STEP = 256
START_HANDSHAKE = (6192, 6192, 5120, 5120)
END_HANDSHAKE = (5632,) * 8
VERSION = (BASE_FREQ, BASE_FREQ)

SSID_MAX = 32
PASSWORD_MAX = 63
TOKEN_MAX = 128


class Security(IntEnum):
    """Значения соответствуют веткам PairingSoundController."""

    WEP = 2
    WPA = 3
    OPEN = 4
    NONE = 5

    @property
    def label(self) -> str:
        return {
            Security.WEP: "WEP",
            Security.WPA: "WPA/WPA2",
            Security.OPEN: "открытая",
            Security.NONE: "без данных сети",
        }[self]


class PairingError(ValueError):
    pass


def random_token(length: int = 16) -> str:
    """Свой xTokenCode вместо паспортного.

    Колонка на этапе провижининга проверяет только, что токен непустой:
    кадр с рандомной строкой она принимает. Длину держим 16 символов —
    как в оригинальном кадре приложения, иначе кадр растягивается
    (16 символов -> 102 символа, 4.08 с).
    """
    alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


@dataclass(frozen=True)
class PairingParams:
    ssid: str = ""
    password: str = ""
    security: Security = Security.WPA
    token: str = ""

    def validate(self) -> None:
        if self.security is not Security.NONE:
            if not self.ssid:
                raise PairingError("SSID не может быть пустым")
            if len(self.ssid.encode("utf-8")) > SSID_MAX:
                raise PairingError(f"SSID длиннее {SSID_MAX} байт")
        if len(self.password.encode("utf-8")) > PASSWORD_MAX:
            raise PairingError(f"Пароль длиннее {PASSWORD_MAX} байт")
        if len(self.token.encode("utf-8")) > TOKEN_MAX:
            raise PairingError(f"xTokenCode длиннее {TOKEN_MAX} байт")
        for value in (self.ssid, self.password, self.token):
            if any(ord(ch) < 0x20 for ch in value):
                raise PairingError("Управляющие символы в данных недопустимы")


# ---------- GF(16) / RS(15,11) ----------
GF_PRIM = 0x13
GF_SIZE = 16
GF_ORDER = GF_SIZE - 1

_EXP = [0] * (GF_SIZE * 2)
_LOG = [0] * GF_SIZE
_x = 1
for _i in range(GF_ORDER):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & GF_SIZE:
        _x ^= GF_PRIM
for _i in range(GF_ORDER, len(_EXP)):
    _EXP[_i] = _EXP[_i - GF_ORDER]


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _poly_mul(p: list[int], q: list[int]) -> list[int]:
    out = [0] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        if a:
            for j, b in enumerate(q):
                out[i + j] ^= _gf_mul(a, b)
    return out


def _generator(nsym: int = 4, base: int = 1) -> list[int]:
    gen = [1]
    for i in range(nsym):
        gen = _poly_mul(gen, [1, _EXP[(base + i) % GF_ORDER]])
    return gen


def rs_encode(data: list[int], nsym: int = 4, base: int = 1) -> list[int]:
    gen = _generator(nsym, base)
    msg = list(data) + [0] * nsym
    for i in range(len(data)):
        coef = msg[i]
        if coef:
            for j in range(1, len(gen)):
                msg[i + j] ^= _gf_mul(gen[j], coef)
    return msg[-nsym:]


def rs_syndromes_zero(block: list[int], nsym: int = 4, base: int = 1) -> bool:
    for i in range(nsym):
        a = _EXP[(base + i) % GF_ORDER]
        acc = 0
        for coef in block:
            acc = _gf_mul(acc, a) ^ coef
        if acc:
            return False
    return True


def java_hash(text: str) -> int:
    h = 0
    raw = text.encode("utf-16-be")
    for i in range(0, len(raw), 2):
        h = (31 * h + ((raw[i] << 8) | raw[i + 1])) & 0xFFFFFFFF
    return h - (1 << 32) if h & 0x80000000 else h


def _lp(out: bytearray, value: str) -> None:
    raw = value.encode("utf-8")
    if len(raw) > 255:
        raise PairingError("строка длиннее 255 байт")
    out.append(len(raw))
    out += raw


def build_payload(params: PairingParams) -> bytes:
    params.validate()
    out = bytearray([(int(params.security) - 1) & 0xFF])
    if params.security is not Security.NONE:
        if params.security is Security.OPEN:
            h = java_hash(params.ssid)
            rem = -(abs(h) % 32767) if h < 0 else h % 32767
            out += struct.pack("<h", rem)
        else:
            _lp(out, params.ssid)
        _lp(out, params.password)
    _lp(out, params.token)
    out += struct.pack("<H", zlib.crc32(bytes(out)) & 0xFFFF)
    return bytes(out)


def to_nibbles(data: bytes) -> list[int]:
    out: list[int] = []
    for byte in data:
        out.append(byte >> 4)
        out.append(byte & 0xF)
    return out


def encode_nibbles(nibbles: list[int]) -> list[int]:
    out: list[int] = []
    for i in range(0, len(nibbles), 11):
        block = nibbles[i:i + 11]
        out.extend(block)
        out.extend(rs_encode(block))
    return out


def tone_freqs(params: PairingParams) -> tuple[bytes, list[int]]:
    payload = build_payload(params)
    data = encode_nibbles(to_nibbles(payload))
    freqs = (
        list(START_HANDSHAKE)
        + list(VERSION)
        + [BASE_FREQ + FREQ_STEP * n for n in data]
        + list(END_HANDSHAKE)
    )
    return payload, freqs


def render_pcm(freqs: list[int]) -> list[int]:
    pcm: list[int] = []
    for freq in freqs:
        step = 2.0 * math.pi * freq / SAMPLE_RATE
        pcm.extend(int(32767 * math.sin(step * k)) for k in range(SYMBOL_SAMPLES))
    return pcm


def wav_bytes(pcm: list[int]) -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(SAMPLE_RATE)
        wav.writeframes(struct.pack("<%dh" % len(pcm), *pcm))
    return buf.getvalue()


def ogg_opus(pcm: list[int], bitrate: str = "96k") -> bytes:
    """WAV -> OGG/Opus 48 кГц (формат voice message Telegram)."""
    with tempfile.TemporaryDirectory(prefix="quasar-pair-") as tmp:
        src = Path(tmp) / "src.wav"
        dst = Path(tmp) / "voice.ogg"
        src.write_bytes(wav_bytes(pcm))
        subprocess.run(
            [
                "ffmpeg", "-y", "-loglevel", "error",
                "-i", str(src),
                "-ac", "1", "-ar", "48000",
                "-c:a", "libopus", "-b:a", bitrate,
                "-application", "audio",
                str(dst),
            ],
            check=True,
            timeout=30,
        )
        return dst.read_bytes()


@dataclass(frozen=True)
class RenderedPairing:
    payload: bytes
    freqs: list[int]
    pcm: list[int]
    duration: float
    symbols: int

    def wav(self) -> bytes:
        return wav_bytes(self.pcm)

    def voice(self) -> bytes:
        return ogg_opus(self.pcm)


def render(params: PairingParams) -> RenderedPairing:
    payload, freqs = tone_freqs(params)
    pcm = render_pcm(freqs)
    return RenderedPairing(
        payload=payload,
        freqs=freqs,
        pcm=pcm,
        duration=len(pcm) / SAMPLE_RATE,
        symbols=len(freqs),
    )


def decode_freqs(pcm: list[int]) -> list[int]:
    """Демодулятор Гёрцеля — для тестов и проверки записи."""
    candidates = sorted(
        {BASE_FREQ + FREQ_STEP * n for n in range(16)}
        | set(START_HANDSHAKE)
        | set(END_HANDSHAKE)
    )
    result: list[int] = []
    for start in range(0, len(pcm) - SYMBOL_SAMPLES + 1, SYMBOL_SAMPLES):
        chunk = pcm[start:start + SYMBOL_SAMPLES]
        best, best_power = None, -1.0
        for freq in candidates:
            w = 2.0 * math.pi * freq / SAMPLE_RATE
            c = 2.0 * math.cos(w)
            s1 = s2 = 0.0
            for sample in chunk:
                s0 = sample + c * s1 - s2
                s2, s1 = s1, s0
            power = s1 * s1 + s2 * s2 - c * s1 * s2
            if power > best_power:
                best, best_power = freq, power
        result.append(best)
    return result


def decode_payload(freqs: list[int], payload_len: int) -> bytes:
    """Снимает RS-чётность и собирает payload (без коррекции ошибок)."""
    body = freqs[len(START_HANDSHAKE) + len(VERSION):-len(END_HANDSHAKE)]
    nibbles = [(f - BASE_FREQ) // FREQ_STEP for f in body]
    info: list[int] = []
    pos = 0
    remaining = payload_len * 2
    while remaining > 0:
        take = min(11, remaining)
        info.extend(nibbles[pos:pos + take])
        pos += take + 4
        remaining -= take
    return bytes((info[i] << 4) | info[i + 1] for i in range(0, len(info) - 1, 2))


# ---------- приём и разбор записи ----------
def _goertzel(samples: list[int], freq: float, rate: int) -> float:
    w = 2.0 * math.pi * freq / rate
    c = 2.0 * math.cos(w)
    s1 = s2 = 0.0
    for value in samples:
        s0 = value + c * s1 - s2
        s2, s1 = s1, s0
    return s1 * s1 + s2 * s2 - c * s1 * s2


DATA_FREQS = tuple(BASE_FREQ + FREQ_STEP * n for n in range(16))
ALL_FREQS = tuple(sorted(set(DATA_FREQS) | set(START_HANDSHAKE) | set(END_HANDSHAKE)))


def _reference(rate: int) -> list[int]:
    tones = list(START_HANDSHAKE) + list(VERSION)
    out: list[int] = []
    for freq in tones:
        step = 2.0 * math.pi * freq / rate
        out.extend(int(12000 * math.sin(step * k)) for k in range(int(rate * 0.04)))
    return out


def _onset(samples: list[int], rate: int) -> int:
    win = max(1, rate // 100)
    env = []
    for i in range(0, len(samples) - win, win):
        chunk = samples[i:i + win]
        env.append(sum(v * v for v in chunk) / len(chunk))
    peak = max(env) if env else 0
    if peak <= 0:
        raise PairingError("в записи тишина")
    threshold = peak * 0.10
    for i, value in enumerate(env):
        if value > threshold:
            return i * win
    return 0


def _header_score(samples: list[int], offset: int, rate: int) -> float:
    win = int(rate * 0.04)
    expected = list(START_HANDSHAKE) + list(VERSION)
    score = 0.0
    for i, freq in enumerate(expected):
        pos = offset + i * win
        chunk = samples[pos:pos + win]
        if len(chunk) < win // 2:
            return -1.0
        score += _goertzel(chunk, freq, rate)
    return score


def _find_start(samples: list[int], rate: int) -> int:
    onset = _onset(samples, rate)
    best_score, best_off = -1.0, onset
    step = max(1, rate // 400)
    for delta in range(-rate // 5, rate // 5 + 1, step):
        off = onset + delta
        if off < 0:
            continue
        score = _header_score(samples, off, rate)
        if score > best_score:
            best_score, best_off = score, off
    return best_off


def _symbols(samples: list[int], start: int, rate: int, limit: int) -> list[int]:
    win = int(rate * 0.04)
    out: list[int] = []
    for i in range(limit):
        pos = start + i * win
        chunk = samples[pos:pos + win]
        if len(chunk) < win // 2:
            break
        best_freq, best_power = None, -1.0
        for freq in ALL_FREQS:
            power = _goertzel(chunk, freq, rate)
            if power > best_power:
                best_freq, best_power = freq, power
        out.append(best_freq)
    return out


def _nearest_handshake(freq: int) -> int:
    return min(START_HANDSHAKE + END_HANDSHAKE, key=lambda f: abs(f - freq))


def _decode_block(block: list[int]) -> tuple[list[int] | None, int]:
    if rs_syndromes_zero(block):
        return block, 0
    n = len(block)
    for p in range(n):
        for v in range(16):
            if v == block[p]:
                continue
            trial = list(block)
            trial[p] = v
            if rs_syndromes_zero(trial):
                return trial, 1
    for p in range(n):
        for q in range(p + 1, n):
            for vp in range(16):
                if vp == block[p]:
                    continue
                for vq in range(16):
                    if vq == block[q]:
                        continue
                    trial = list(block)
                    trial[p] = vp
                    trial[q] = vq
                    if rs_syndromes_zero(trial):
                        return trial, 2
    return None, -1


@dataclass
class DecodedPairing:
    params: PairingParams
    payload: bytes
    errors: int
    crc_ok: bool
    symbols: int
    kind: str = "wifi"          # wifi | auth | intro | unknown


def decode_recording(path: str | Path) -> DecodedPairing:
    """Разбирает wav/ogg с записью кода. Бросает PairingError, если не распознал."""
    with tempfile.TemporaryDirectory(prefix="quasar-decode-") as tmp:
        wav_path = Path(tmp) / "in.wav"
        subprocess.run(
            ["ffmpeg", "-y", "-loglevel", "error", "-i", str(path),
             "-ac", "1", "-ar", str(SAMPLE_RATE), "-c:a", "pcm_s16le", str(wav_path)],
            check=True, timeout=60,
        )
        with wave.open(str(wav_path)) as wav:
            frames = wav.readframes(wav.getnframes())
    samples = list(struct.unpack("<%dh" % (len(frames) // 2), frames))

    start = _find_start(samples, SAMPLE_RATE)
    freqs = _symbols(samples, start, SAMPLE_RATE, limit=400)
    if freqs[:4] != list(START_HANDSHAKE):
        raise PairingError("не нашёл стартовый маркер — запись тихая или обрезана")

    end_idx = None
    for i in range(len(freqs) - 8, 5, -1):
        window = freqs[i:i + 8]
        if window.count(END_HANDSHAKE[0]) >= 6:
            end_idx = i
            break
    if end_idx is None:
        raise PairingError("не нашёл конец кадра — запиши ещё раз, ближе к динамику")

    body = freqs[6:end_idx]
    nibbles = [
        (min(DATA_FREQS, key=lambda f: abs(f - freq)) - BASE_FREQ) // FREQ_STEP
        for freq in body
    ]
    blocks = [nibbles[i:i + 15] for i in range(0, len(nibbles), 15)]
    info: list[int] = []
    errors = 0
    for block in blocks:
        if len(block) < 5:
            break
        fixed, count = _decode_block(block)
        if fixed is None:
            raise PairingError("слишком много ошибок в записи — перезапиши ближе к динамику")
        errors += count
        info.extend(fixed[:-4])

    if len(info) < 12:
        raise PairingError("кадр слишком короткий")
    raw = bytes((info[i] << 4) | info[i + 1] for i in range(0, len(info) - 1, 2))
    crc_ok = raw[-2:] == struct.pack("<H", zlib.crc32(raw[:-2]) & 0xFFFF)
    payload = raw[:-2] if crc_ok else raw

    pos = 0
    wifi_type = payload[pos] + 1
    pos += 1
    ssid = password = ""
    if wifi_type != 5:
        if wifi_type == 4:
            pos += 2
        else:
            length = payload[pos]
            pos += 1
            ssid = payload[pos:pos + length].decode("utf-8", "replace")
            pos += length
        length = payload[pos]
        pos += 1
        password = payload[pos:pos + length].decode("utf-8", "replace")
        pos += length
    length = payload[pos]
    pos += 1
    token = payload[pos:pos + length].decode("utf-8", "replace")

    security = {2: Security.WEP, 3: Security.WPA, 4: Security.OPEN, 5: Security.NONE}.get(
        wifi_type, Security.WPA
    )
    kind = "wifi" if 1 <= wifi_type <= 4 else ("auth" if wifi_type == 5 else "unknown")
    return DecodedPairing(
        params=PairingParams(ssid=ssid, password=password, security=security, token=token),
        payload=raw,
        errors=errors,
        crc_ok=crc_ok,
        symbols=len(freqs),
        kind=kind,
    )
