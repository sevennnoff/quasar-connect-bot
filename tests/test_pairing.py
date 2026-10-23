import io
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import wave
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pairing  # noqa: E402


class PayloadTests(unittest.TestCase):
    def test_wpa_layout(self):
        params = pairing.PairingParams("TestNet", "12345678", pairing.Security.WPA)
        payload = pairing.build_payload(params)
        self.assertEqual(payload[0], 2)                      # WPA -> 3 - 1
        self.assertEqual(payload[1], 7)
        self.assertEqual(payload[2:9], b"TestNet")
        self.assertEqual(payload[9], 8)
        self.assertEqual(payload[10:18], b"12345678")
        self.assertEqual(payload[18], 0)                     # пустой token
        crc = struct.unpack("<H", payload[-2:])[0]
        self.assertEqual(crc, zlib.crc32(payload[:-2]) & 0xFFFF)

    def test_open_uses_hash(self):
        params = pairing.PairingParams("OpenNet", "", pairing.Security.OPEN)
        payload = pairing.build_payload(params)
        self.assertEqual(payload[0], 3)
        hashed = struct.unpack("<h", payload[1:3])[0]
        h = pairing.java_hash("OpenNet")
        self.assertEqual(hashed, h % 32767)
        self.assertEqual(payload[3], 0)                      # пустой пароль
        self.assertEqual(payload[4], 0)                      # пустой token

    def test_none_only_token(self):
        params = pairing.PairingParams("", "", pairing.Security.NONE, token="tok")
        payload = pairing.build_payload(params)
        self.assertEqual(payload[0], 4)
        self.assertEqual(payload[1:5], b"\x03tok")

    def test_crc_is_big_endian(self):
        payload = pairing.build_payload(pairing.PairingParams("A", "B"))
        self.assertEqual(payload[-2:], struct.pack("<H", zlib.crc32(payload[:-2]) & 0xFFFF))

    def test_validation(self):
        with self.assertRaises(pairing.PairingError):
            pairing.build_payload(pairing.PairingParams(""))
        with self.assertRaises(pairing.PairingError):
            pairing.build_payload(pairing.PairingParams("A" * 33, "x"))

    def test_unicode_ssid(self):
        params = pairing.PairingParams("Дом-5G", "Пароль123", pairing.Security.WPA)
        payload = pairing.build_payload(params)
        self.assertEqual(payload[1], len("Дом-5G".encode()))


class ReedSolomonTests(unittest.TestCase):
    def test_syndromes_zero(self):
        for data in ([0] * 11, list(range(11)), [15] * 11, [1, 2, 3]):
            block = data + pairing.rs_encode(data)
            self.assertTrue(pairing.rs_syndromes_zero(block))

    def test_block_shape(self):
        nibbles = list(range(16)) * 2            # 32 ниббла
        encoded = pairing.encode_nibbles(nibbles)
        self.assertEqual(len(encoded), 11 + 4 + 11 + 4 + 10 + 4)


class FrameTests(unittest.TestCase):
    def test_frame_structure(self):
        params = pairing.PairingParams("HomeWiFi", "qwerty12345", pairing.Security.WPA)
        payload, freqs = pairing.tone_freqs(params)
        self.assertEqual(freqs[:4], list(pairing.START_HANDSHAKE))
        self.assertEqual(freqs[4:6], list(pairing.VERSION))
        self.assertEqual(freqs[-8:], list(pairing.END_HANDSHAKE))
        self.assertTrue(all(f >= pairing.BASE_FREQ for f in freqs[6:-8]))

    def test_roundtrip(self):
        params = pairing.PairingParams("HomeWiFi", "qwerty12345", pairing.Security.WPA)
        rendered = pairing.render(params)
        got = pairing.decode_freqs(rendered.pcm)
        self.assertEqual(got, rendered.freqs)
        self.assertEqual(pairing.decode_payload(got, len(rendered.payload)), rendered.payload)

    def test_random_token_roundtrip(self):
        token = pairing.random_token()
        self.assertTrue(token)
        self.assertLessEqual(len(token.encode("utf-8")), pairing.TOKEN_MAX)
        self.assertNotEqual(pairing.random_token(), token)
        params = pairing.PairingParams("HomeWiFi", "qwerty12345", pairing.Security.WPA, token=token)
        rendered = pairing.render(params)
        got = pairing.decode_freqs(rendered.pcm)
        self.assertEqual(got, rendered.freqs)
        decoded = pairing.decode_payload(got, len(rendered.payload))
        self.assertEqual(decoded, rendered.payload)
        self.assertIn(token.encode("utf-8"), decoded)

    def test_duration(self):
        rendered = pairing.render(pairing.PairingParams("Net", "pass"))
        self.assertAlmostEqual(rendered.duration, rendered.symbols * 0.04, places=3)
        self.assertGreater(rendered.duration, 1.0)


class WavTests(unittest.TestCase):
    def test_wav_header(self):
        rendered = pairing.render(pairing.PairingParams("Net", "pass"))
        raw = rendered.wav()
        with wave.open(io.BytesIO(raw)) as wav:
            self.assertEqual(wav.getnchannels(), 1)
            self.assertEqual(wav.getframerate(), pairing.SAMPLE_RATE)
            self.assertEqual(wav.getsampwidth(), 2)
            self.assertEqual(wav.getnframes(), len(rendered.pcm))


@unittest.skipUnless(shutil.which("ffmpeg"), "ffmpeg не установлен")
class OpusTests(unittest.TestCase):
    def test_voice_survives_opus(self):
        params = pairing.PairingParams("HomeWiFi", "qwerty12345", pairing.Security.WPA)
        rendered = pairing.render(params)
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src.wav"
            dec = Path(tmp) / "dec.wav"
            src.write_bytes(rendered.wav())
            (Path(tmp) / "voice.ogg").write_bytes(rendered.voice())
            subprocess.run(
                ["ffmpeg", "-y", "-loglevel", "error", "-i", str(Path(tmp) / "voice.ogg"),
                 "-ac", "1", "-ar", "16000", "-c:a", "pcm_s16le", str(dec)],
                check=True,
            )
            with wave.open(str(dec)) as wav:
                frames = wav.readframes(wav.getnframes())
            pcm = list(struct.unpack("<%dh" % (len(frames) // 2), frames))
        got = pairing.decode_freqs(pcm)
        self.assertEqual(got, rendered.freqs)


if __name__ == "__main__":
    unittest.main(verbosity=2)


@unittest.skipUnless(shutil.which("ffmpeg"), "ffmpeg не установлен")
class DecodeTests(unittest.TestCase):
    def test_decodes_own_voice(self):
        params = pairing.PairingParams("2G", "9RZ58HIS", pairing.Security.WPA, token="abc123")
        rendered = pairing.render(params)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "voice.ogg"
            path.write_bytes(rendered.voice())
            decoded = pairing.decode_recording(path)
        self.assertEqual(decoded.params.ssid, params.ssid)
        self.assertEqual(decoded.params.password, params.password)
        self.assertEqual(decoded.params.token, params.token)
        self.assertTrue(decoded.crc_ok)
        self.assertEqual(decoded.errors, 0)
