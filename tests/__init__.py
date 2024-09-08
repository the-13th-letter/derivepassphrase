# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import base64
import contextlib
import importlib.util
import json
import os
import stat
import tempfile
import zipfile
from typing import TYPE_CHECKING

import pytest
from typing_extensions import NamedTuple, Self, assert_never

from derivepassphrase import _types, cli

__all__ = ()

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    import click.testing
    from typing_extensions import Any, TypedDict

    class SSHTestKey(TypedDict):
        private_key: bytes
        public_key: bytes | str
        public_key_data: bytes
        expected_signature: bytes | None
        derived_passphrase: bytes | str | None


SUPPORTED_KEYS: Mapping[str, SSHTestKey] = {
    'ed25519': {
        'private_key': rb"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCBeIFoJtYCSF8P/zJIb+TBMIncHGpFBgnpCQ/7whJpdgAAAKDweO7H8Hju
xwAAAAtzc2gtZWQyNTUxOQAAACCBeIFoJtYCSF8P/zJIb+TBMIncHGpFBgnpCQ/7whJpdg
AAAEAbM/A869nkWZbe2tp3Dm/L6gitvmpH/aRZt8sBII3ExYF4gWgm1gJIXw//Mkhv5MEw
idwcakUGCekJD/vCEml2AAAAG3Rlc3Qga2V5IHdpdGhvdXQgcGFzc3BocmFzZQEC
-----END OPENSSH PRIVATE KEY-----
""",
        'public_key': rb"""ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIF4gWgm1gJIXw//Mkhv5MEwidwcakUGCekJD/vCEml2 test key without passphrase
""",  # noqa: E501
        'public_key_data': bytes.fromhex("""
            00 00 00 0b 73 73 68 2d 65 64 32 35 35 31 39
            00 00 00 20
            81 78 81 68 26 d6 02 48 5f 0f ff 32 48 6f e4 c1
            30 89 dc 1c 6a 45 06 09 e9 09 0f fb c2 12 69 76
"""),
        'expected_signature': bytes.fromhex("""
            00 00 00 0b 73 73 68 2d 65 64 32 35 35 31 39
            00 00 00 40
            f0 98 19 80 6c 1a 97 d5 26 03 6e cc e3 65 8f 86
            66 07 13 19 13 09 21 33 33 f9 e4 36 53 1d af fd
            0d 08 1f ec f8 73 9b 8c 5f 55 39 16 7c 53 54 2c
            1e 52 bb 30 ed 7f 89 e2 2f 69 51 55 d8 9e a6 02
        """),
        'derived_passphrase': rb'8JgZgGwal9UmA27M42WPhmYHExkTCSEzM/nkNlMdr/0NCB/s+HObjF9VORZ8U1QsHlK7MO1/ieIvaVFV2J6mAg==',  # noqa: E501
    },
    # Currently only supported by PuTTY (which is deficient in other
    # niceties of the SSH agent and the agent's client).
    'ed448': {
        'private_key': rb"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAASgAAAAlz
c2gtZWQ0NDgAAAA54vZy009Wu8wExjvEb3hqtLz1GO/+d5vmGUbErWQ4AUO9mYLT
zHJHc2m4s+yWzP29Cc3EcxizLG8AAAAA8BdhfCcXYXwnAAAACXNzaC1lZDQ0OAAA
ADni9nLTT1a7zATGO8RveGq0vPUY7/53m+YZRsStZDgBQ72ZgtPMckdzabiz7JbM
/b0JzcRzGLMsbwAAAAByM7GIMRvWJB3YD6SIpAF2uudX4ozZe0X917wPwiBrs373
9TM1n94Nib6hrxGNmCk2iBQDe2KALPgA4vZy009Wu8wExjvEb3hqtLz1GO/+d5vm
GUbErWQ4AUO9mYLTzHJHc2m4s+yWzP29Cc3EcxizLG8AAAAAG3Rlc3Qga2V5IHdp
dGhvdXQgcGFzc3BocmFzZQECAwQFBgcICQ==
-----END OPENSSH PRIVATE KEY-----
""",
        'public_key': rb"""ssh-ed448 AAAACXNzaC1lZDQ0OAAAADni9nLTT1a7zATGO8RveGq0vPUY7/53m+YZRsStZDgBQ72ZgtPMckdzabiz7JbM/b0JzcRzGLMsbwA= test key without passphrase
""",  # noqa: E501
        'public_key_data': bytes.fromhex("""
            00 00 00 09 73 73 68 2d 65 64 34 34 38
            00 00 00 39
            e2 f6 72 d3 4f 56 bb cc 04 c6 3b c4 6f 78 6a b4
            bc f5 18 ef fe 77 9b e6 19 46 c4 ad 64 38 01 43
            bd 99 82 d3 cc 72 47 73 69 b8 b3 ec 96 cc fd bd
            09 cd c4 73 18 b3 2c 6f 00
        """),
        'expected_signature': bytes.fromhex("""
            00 00 00 09 73 73 68 2d 65 64 34 34 38
            00 00 00 72 06 86
            f4 64 a4 a6 ba d9 c3 22 c4 93 49 99 fc 11 de 67
            97 08 f2 d8 b7 3c 2c 13 e7 c5 1c 1e 92 a6 0e d8
            2f 6d 81 03 82 00 e3 72 e4 32 6d 72 d2 6d 32 84
            3f cc a9 1e 57 2c 00 9a b3 99 de 45 da ce 2e d1
            db e5 89 f3 35 be 24 58 90 c6 ca 04 f0 db 88 80
            db bd 77 7c 80 20 7f 3a 48 61 f6 1f ae a9 5e 53
            7b e0 9d 93 1e ea dc eb b5 cd 56 4c ea 8f 08 00
        """),
        'derived_passphrase': rb'Bob0ZKSmutnDIsSTSZn8Ed5nlwjy2Lc8LBPnxRwekqYO2C9tgQOCAONy5DJtctJtMoQ/zKkeVywAmrOZ3kXazi7R2+WJ8zW+JFiQxsoE8NuIgNu9d3yAIH86SGH2H66pXlN74J2THurc67XNVkzqjwgA',  # noqa: E501
    },
    'rsa': {
        'private_key': rb"""-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
""",
        'public_key': rb"""ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCxoe7pezhxWy4NI0mUwKqg9WCYOAS+IjxN9eYcqpfcmQiojcuy9XsiN/xYJ1O94SrsKS5mEia2xHnYA4RUChTyYNcM2v6cnnBQ/N/VQhpGMN7SVxdbhKUXTWFCwbjBgO6rGyHB6WtoH8vd7TOEPt+NgcXwhsWyoaUUdYTA62V+GF9vEmxMaC4ubgDz+B0QkPnauSoNxmkhcIe0lsLNb1pClZyz88PDnKXCX/d0HuN/HJ+sbPg7dCvOyqFYSyKn3uY6bCXqoIdurxXzH3O7z0P8f5sbmKOrGGKNuNxVRbeVl/D/3uDL0nqsbfUc1qvkfwbJwtMXC4IV6kOZMSk2BAsqh7x48gQ+rhYeEVSi8F3CWs4HJQoqrGt7K9a3mCSlMBHP70u3w6ME7eumoryxlUofewTd17ZEkzdX08l2ZlKzZvwQUrc+xQZ2Uw8z2mfW6Ti4gi0pYGaig7Ke4PwuXpo/C5YAWfeXycsvJZ2uaYRjMdZeJGNAnHLUGLkBscw5aI8= test key without passphrase
""",  # noqa: E501
        'public_key_data': bytes.fromhex("""
            00 00 00 07 73 73 68 2d 72 73 61
            00 00 00 03 01 00 01
            00 00 01 81 00
            b1 a1 ee e9 7b 38 71 5b 2e 0d 23 49 94 c0 aa a0
            f5 60 98 38 04 be 22 3c 4d f5 e6 1c aa 97 dc 99
            08 a8 8d cb b2 f5 7b 22 37 fc 58 27 53 bd e1 2a
            ec 29 2e 66 12 26 b6 c4 79 d8 03 84 54 0a 14 f2
            60 d7 0c da fe 9c 9e 70 50 fc df d5 42 1a 46 30
            de d2 57 17 5b 84 a5 17 4d 61 42 c1 b8 c1 80 ee
            ab 1b 21 c1 e9 6b 68 1f cb dd ed 33 84 3e df 8d
            81 c5 f0 86 c5 b2 a1 a5 14 75 84 c0 eb 65 7e 18
            5f 6f 12 6c 4c 68 2e 2e 6e 00 f3 f8 1d 10 90 f9
            da b9 2a 0d c6 69 21 70 87 b4 96 c2 cd 6f 5a 42
            95 9c b3 f3 c3 c3 9c a5 c2 5f f7 74 1e e3 7f 1c
            9f ac 6c f8 3b 74 2b ce ca a1 58 4b 22 a7 de e6
            3a 6c 25 ea a0 87 6e af 15 f3 1f 73 bb cf 43 fc
            7f 9b 1b 98 a3 ab 18 62 8d b8 dc 55 45 b7 95 97
            f0 ff de e0 cb d2 7a ac 6d f5 1c d6 ab e4 7f 06
            c9 c2 d3 17 0b 82 15 ea 43 99 31 29 36 04 0b 2a
            87 bc 78 f2 04 3e ae 16 1e 11 54 a2 f0 5d c2 5a
            ce 07 25 0a 2a ac 6b 7b 2b d6 b7 98 24 a5 30 11
            cf ef 4b b7 c3 a3 04 ed eb a6 a2 bc b1 95 4a 1f
            7b 04 dd d7 b6 44 93 37 57 d3 c9 76 66 52 b3 66
            fc 10 52 b7 3e c5 06 76 53 0f 33 da 67 d6 e9 38
            b8 82 2d 29 60 66 a2 83 b2 9e e0 fc 2e 5e 9a 3f
            0b 96 00 59 f7 97 c9 cb 2f 25 9d ae 69 84 63 31
            d6 5e 24 63 40 9c 72 d4 18 b9 01 b1 cc 39 68 8f
"""),
        'expected_signature': bytes.fromhex("""
            00 00 00 07 73 73 68 2d 72 73 61
            00 00 01 80
            a2 10 7c 2e f6 bb 53 a8 74 2a a1 19 99 ad 81 be
            79 9c ed d6 9d 09 4e 6e c5 18 48 33 90 77 99 68
            f7 9e 03 5a cd 4e 18 eb 89 7d 85 a2 ee ae 4a 92
            f6 6f ce b9 fe 86 7f 2a 6b 31 da 6e 1a fe a2 a5
            88 b8 44 7f a1 76 73 b3 ec 75 b5 d0 a6 b9 15 97
            65 09 13 7d 94 21 d1 fb 5d 0f 8b 23 04 77 c2 c3
            55 22 b1 a0 09 8a f5 38 2a d6 7f 1b 87 29 a0 25
            d3 25 6f cb 64 61 07 98 dc 14 c5 84 f8 92 24 5e
            50 11 6b 49 e5 f0 cc 29 cb 29 a9 19 d8 a7 71 1f
            91 0b 05 b1 01 4b c2 5f 00 a5 b6 21 bf f8 2c 9d
            67 9b 47 3b 0a 49 6b 79 2d fc 1d ec 0c b0 e5 27
            22 d5 a9 f8 d3 c3 f9 df 48 68 e9 fb ef 3c dc 26
            bf cf ea 29 43 01 a6 e3 c5 51 95 f4 66 6d 8a 55
            e2 47 ec e8 30 45 4c ae 47 e7 c9 a4 21 8b 64 ba
            b6 88 f6 21 f8 73 b9 cb 11 a1 78 75 92 c6 5a e5
            64 fe ed 42 d9 95 99 e6 2b 6f 3c 16 3c 28 74 a4
            72 2f 0d 3f 2c 33 67 aa 35 19 8e e7 b5 11 2f b3
            f7 6a c5 02 e2 6f a3 42 e3 62 19 99 03 ea a5 20
            e7 a1 e3 bc c8 06 a3 b5 7c d6 76 5d df 6f 60 46
            83 2a 08 00 d6 d3 d9 a4 c1 41 8c f8 60 56 45 81
            da 3b a2 16 1f 9e 4e 75 83 17 da c3 53 c3 3e 19
            a4 1b bc d2 29 b8 78 61 2b 78 e6 b1 52 b0 d5 ec
            de 69 2c 48 62 d9 fd d1 9b 6b b0 49 db d3 ff 38
            e7 10 d9 2d ce 9f 0d 5e 09 7b 37 d2 7b c3 bf ce
"""),
        'derived_passphrase': rb'ohB8Lva7U6h0KqEZma2Bvnmc7dadCU5uxRhIM5B3mWj3ngNazU4Y64l9haLurkqS9m/Ouf6GfyprMdpuGv6ipYi4RH+hdnOz7HW10Ka5FZdlCRN9lCHR+10PiyMEd8LDVSKxoAmK9Tgq1n8bhymgJdMlb8tkYQeY3BTFhPiSJF5QEWtJ5fDMKcspqRnYp3EfkQsFsQFLwl8ApbYhv/gsnWebRzsKSWt5Lfwd7Ayw5Sci1an408P530ho6fvvPNwmv8/qKUMBpuPFUZX0Zm2KVeJH7OgwRUyuR+fJpCGLZLq2iPYh+HO5yxGheHWSxlrlZP7tQtmVmeYrbzwWPCh0pHIvDT8sM2eqNRmO57URL7P3asUC4m+jQuNiGZkD6qUg56HjvMgGo7V81nZd329gRoMqCADW09mkwUGM+GBWRYHaO6IWH55OdYMX2sNTwz4ZpBu80im4eGEreOaxUrDV7N5pLEhi2f3Rm2uwSdvT/zjnENktzp8NXgl7N9J7w7/O',  # noqa: E501
    },
}

UNSUITABLE_KEYS: Mapping[str, SSHTestKey] = {
    'dsa1024': {
        'private_key': rb"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsQAAAAdzc2gtZH
NzAAAAgQC7KAZXqBGNVLBQPrcMYAoNW54BhD8aIhe7BDWYzJcsaMt72VKSkguZ8+XR7nRa
0C/ZsBi+uJp0dpxy9ZMTOWX4u5YPMeQcXEdGExZIfimGqSOAsy6fCld2IfJZJZExcCmhe9
Ssjsd3YSAPJRluOXFQc95MZoR5hMwlIDD8QzrE7QAAABUA99nOZOgd7aHMVGoXpUEBcn7H
ossAAACALr2Ag3hxM3rKdxzVUw8fX0VVPXO+3+Kr8hGe0Kc/7NwVaBVL1GQ8fenBuWynpA
UbH0wo3h1wkB/8hX6p+S8cnu5rIBlUuVNwLw/bIYohK98LfqTYK/V+g6KD+8m34wvEiXZm
qywY54n2bksch1Nqvj/tNpLzExSx/XS0kSM1aigAAACAbQNRPcVEuGDrEcf+xg5tgAejPX
BPXr/Jss+Chk64km3mirMYjAWyWYtVcgT+7hOYxtYRin8LyMLqKRmqa0Q5UrvDfChgLhvs
G9YSb/Mpw5qm8PiHSafwhkaz/te3+8hKogqoe7sd+tCF06IpJr5k70ACiNtRGqssNF8Elr
l1efYAAAH4swlfVrMJX1YAAAAHc3NoLWRzcwAAAIEAuygGV6gRjVSwUD63DGAKDVueAYQ/
GiIXuwQ1mMyXLGjLe9lSkpILmfPl0e50WtAv2bAYvriadHaccvWTEzll+LuWDzHkHFxHRh
MWSH4phqkjgLMunwpXdiHyWSWRMXApoXvUrI7Hd2EgDyUZbjlxUHPeTGaEeYTMJSAw/EM6
xO0AAAAVAPfZzmToHe2hzFRqF6VBAXJ+x6LLAAAAgC69gIN4cTN6yncc1VMPH19FVT1zvt
/iq/IRntCnP+zcFWgVS9RkPH3pwblsp6QFGx9MKN4dcJAf/IV+qfkvHJ7uayAZVLlTcC8P
2yGKISvfC36k2Cv1foOig/vJt+MLxIl2ZqssGOeJ9m5LHIdTar4/7TaS8xMUsf10tJEjNW
ooAAAAgG0DUT3FRLhg6xHH/sYObYAHoz1wT16/ybLPgoZOuJJt5oqzGIwFslmLVXIE/u4T
mMbWEYp/C8jC6ikZqmtEOVK7w3woYC4b7BvWEm/zKcOapvD4h0mn8IZGs/7Xt/vISqIKqH
u7HfrQhdOiKSa+ZO9AAojbURqrLDRfBJa5dXn2AAAAFQDJHfenj4EJ9WkehpdJatPBlqCW
0gAAABt0ZXN0IGtleSB3aXRob3V0IHBhc3NwaHJhc2UBAgMEBQYH
-----END OPENSSH PRIVATE KEY-----
""",
        'public_key': rb"""ssh-dss AAAAB3NzaC1kc3MAAACBALsoBleoEY1UsFA+twxgCg1bngGEPxoiF7sENZjMlyxoy3vZUpKSC5nz5dHudFrQL9mwGL64mnR2nHL1kxM5Zfi7lg8x5BxcR0YTFkh+KYapI4CzLp8KV3Yh8lklkTFwKaF71KyOx3dhIA8lGW45cVBz3kxmhHmEzCUgMPxDOsTtAAAAFQD32c5k6B3tocxUahelQQFyfseiywAAAIAuvYCDeHEzesp3HNVTDx9fRVU9c77f4qvyEZ7Qpz/s3BVoFUvUZDx96cG5bKekBRsfTCjeHXCQH/yFfqn5Lxye7msgGVS5U3AvD9shiiEr3wt+pNgr9X6DooP7ybfjC8SJdmarLBjnifZuSxyHU2q+P+02kvMTFLH9dLSRIzVqKAAAAIBtA1E9xUS4YOsRx/7GDm2AB6M9cE9ev8myz4KGTriSbeaKsxiMBbJZi1VyBP7uE5jG1hGKfwvIwuopGaprRDlSu8N8KGAuG+wb1hJv8ynDmqbw+IdJp/CGRrP+17f7yEqiCqh7ux360IXToikmvmTvQAKI21Eaqyw0XwSWuXV59g== test key without passphrase
""",  # noqa: E501
        'public_key_data': bytes.fromhex("""
            00 00 00 07 73 73 68 2d 64 73 73
            00 00 00 81 00
            bb 28 06 57 a8 11 8d 54 b0 50 3e b7 0c 60 0a 0d
            5b 9e 01 84 3f 1a 22 17 bb 04 35 98 cc 97 2c 68
            cb 7b d9 52 92 92 0b 99 f3 e5 d1 ee 74 5a d0 2f
            d9 b0 18 be b8 9a 74 76 9c 72 f5 93 13 39 65 f8
            bb 96 0f 31 e4 1c 5c 47 46 13 16 48 7e 29 86 a9
            23 80 b3 2e 9f 0a 57 76 21 f2 59 25 91 31 70 29
            a1 7b d4 ac 8e c7 77 61 20 0f 25 19 6e 39 71 50
            73 de 4c 66 84 79 84 cc 25 20 30 fc 43 3a c4 ed
            00 00 00 15 00 f7 d9 ce 64
            e8 1d ed a1 cc 54 6a 17 a5 41 01 72 7e c7 a2 cb
            00 00 00 80
            2e bd 80 83 78 71 33 7a ca 77 1c d5 53 0f 1f 5f
            45 55 3d 73 be df e2 ab f2 11 9e d0 a7 3f ec dc
            15 68 15 4b d4 64 3c 7d e9 c1 b9 6c a7 a4 05 1b
            1f 4c 28 de 1d 70 90 1f fc 85 7e a9 f9 2f 1c 9e
            ee 6b 20 19 54 b9 53 70 2f 0f db 21 8a 21 2b df
            0b 7e a4 d8 2b f5 7e 83 a2 83 fb c9 b7 e3 0b c4
            89 76 66 ab 2c 18 e7 89 f6 6e 4b 1c 87 53 6a be
            3f ed 36 92 f3 13 14 b1 fd 74 b4 91 23 35 6a 28
            00 00 00 80
            6d 03 51 3d c5 44 b8 60 eb 11 c7 fe c6 0e 6d 80
            07 a3 3d 70 4f 5e bf c9 b2 cf 82 86 4e b8 92 6d
            e6 8a b3 18 8c 05 b2 59 8b 55 72 04 fe ee 13 98
            c6 d6 11 8a 7f 0b c8 c2 ea 29 19 aa 6b 44 39 52
            bb c3 7c 28 60 2e 1b ec 1b d6 12 6f f3 29 c3 9a
            a6 f0 f8 87 49 a7 f0 86 46 b3 fe d7 b7 fb c8 4a
            a2 0a a8 7b bb 1d fa d0 85 d3 a2 29 26 be 64 ef
            40 02 88 db 51 1a ab 2c 34 5f 04 96 b9 75 79 f6
"""),
        'expected_signature': None,
        'derived_passphrase': None,
    },
    'ecdsa256': {
        'private_key': rb"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTLbU0zDwsk2Dvp+VYIrsNVf5gWwz2S
3SZ8TbxiQRkpnGSVqyIoHJOJc+NQItAa7xlJ/8Z6gfz57Z3apUkaMJm6AAAAuKeY+YinmP
mIAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMttTTMPCyTYO+n5
Vgiuw1V/mBbDPZLdJnxNvGJBGSmcZJWrIigck4lz41Ai0BrvGUn/xnqB/PntndqlSRowmb
oAAAAhAKIl/3n0pKVIxpZkXTGtii782Qr4yIcvHdpxjO/QsIqKAAAAG3Rlc3Qga2V5IHdp
dGhvdXQgcGFzc3BocmFzZQECAwQ=
-----END OPENSSH PRIVATE KEY-----
""",
        'public_key': rb"""ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMttTTMPCyTYO+n5Vgiuw1V/mBbDPZLdJnxNvGJBGSmcZJWrIigck4lz41Ai0BrvGUn/xnqB/PntndqlSRowmbo= test key without passphrase
""",  # noqa: E501
        'public_key_data': bytes.fromhex("""
            00 00 00 13 65 63 64 73 61 2d 73 68 61 32 2d 6e
            69 73 74 70 32 35 36
            00 00 00 08 6e 69 73 74 70 32 35 36
            00 00 00 41 04
            cb 6d 4d 33 0f 0b 24 d8 3b e9 f9 56 08 ae c3 55
            7f 98 16 c3 3d 92 dd 26 7c 4d bc 62 41 19 29 9c
            64 95 ab 22 28 1c 93 89 73 e3 50 22 d0 1a ef 19
            49 ff c6 7a 81 fc f9 ed 9d da a5 49 1a 30 99 ba
"""),
        'expected_signature': None,
        'derived_passphrase': None,
    },
    'ecdsa384': {
        'private_key': rb"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS
1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQSgkOjkAvq7v5vHuj3KBL4/EAWcn5hZ
DyKcbyV0eBMGFq7hKXQlZqIahLVqeMR0QqmkxNJ2rly2VHcXneq3vZ+9fIsWCOdYk5WP3N
ZPzv911Xn7wbEkC7QndD5zKlm4pBUAAADomhj+IZoY/iEAAAATZWNkc2Etc2hhMi1uaXN0
cDM4NAAAAAhuaXN0cDM4NAAAAGEEoJDo5AL6u7+bx7o9ygS+PxAFnJ+YWQ8inG8ldHgTBh
au4Sl0JWaiGoS1anjEdEKppMTSdq5ctlR3F53qt72fvXyLFgjnWJOVj9zWT87/ddV5+8Gx
JAu0J3Q+cypZuKQVAAAAMQD5sTy8p+B1cn/DhOmXquui1BcxvASqzzevkBlbQoBa73y04B
2OdqVOVRkwZWRROz0AAAAbdGVzdCBrZXkgd2l0aG91dCBwYXNzcGhyYXNlAQIDBA==
-----END OPENSSH PRIVATE KEY-----
""",
        'public_key': rb"""ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBKCQ6OQC+ru/m8e6PcoEvj8QBZyfmFkPIpxvJXR4EwYWruEpdCVmohqEtWp4xHRCqaTE0nauXLZUdxed6re9n718ixYI51iTlY/c1k/O/3XVefvBsSQLtCd0PnMqWbikFQ== test key without passphrase
""",  # noqa: E501
        'public_key_data': bytes.fromhex("""
            00 00 00 13
            65 63 64 73 61 2d 73 68 61 32 2d 6e 69 73 74 70
            33 38 34
            00 00 00 08 6e 69 73 74 70 33 38 34
            00 00 00 61 04
            a0 90 e8 e4 02 fa bb bf 9b c7 ba 3d ca 04 be 3f
            10 05 9c 9f 98 59 0f 22 9c 6f 25 74 78 13 06 16
            ae e1 29 74 25 66 a2 1a 84 b5 6a 78 c4 74 42 a9
            a4 c4 d2 76 ae 5c b6 54 77 17 9d ea b7 bd 9f bd
            7c 8b 16 08 e7 58 93 95 8f dc d6 4f ce ff 75 d5
            79 fb c1 b1 24 0b b4 27 74 3e 73 2a 59 b8 a4 15
"""),
        'expected_signature': None,
        'derived_passphrase': None,
    },
}

DUMMY_SERVICE = 'service1'
DUMMY_PASSPHRASE = 'my secret passphrase'
DUMMY_KEY1 = SUPPORTED_KEYS['ed25519']['public_key_data']
DUMMY_KEY1_B64 = base64.standard_b64encode(DUMMY_KEY1).decode('ASCII')
DUMMY_KEY2 = SUPPORTED_KEYS['rsa']['public_key_data']
DUMMY_KEY2_B64 = base64.standard_b64encode(DUMMY_KEY2).decode('ASCII')
DUMMY_KEY3 = SUPPORTED_KEYS['ed448']['public_key_data']
DUMMY_KEY3_B64 = base64.standard_b64encode(DUMMY_KEY3).decode('ASCII')
DUMMY_CONFIG_SETTINGS = {
    'length': 10,
    'upper': 1,
    'lower': 1,
    'repeat': 5,
    'number': 1,
    'space': 1,
    'dash': 1,
    'symbol': 1,
}
DUMMY_RESULT_PASSPHRASE = b'.2V_QJkd o'
DUMMY_RESULT_KEY1 = b'E<b<{ -7iG'
DUMMY_PHRASE_FROM_KEY1_RAW = (
    b'\x00\x00\x00\x0bssh-ed25519'
    b'\x00\x00\x00@\xf0\x98\x19\x80l\x1a\x97\xd5&\x03n'
    b'\xcc\xe3e\x8f\x86f\x07\x13\x19\x13\t!33\xf9\xe46S'
    b'\x1d\xaf\xfd\r\x08\x1f\xec\xf8s\x9b\x8c_U9\x16|ST,'
    b'\x1eR\xbb0\xed\x7f\x89\xe2/iQU\xd8\x9e\xa6\x02'
)
DUMMY_PHRASE_FROM_KEY1 = b'8JgZgGwal9UmA27M42WPhmYHExkTCSEzM/nkNlMdr/0NCB/s+HObjF9VORZ8U1QsHlK7MO1/ieIvaVFV2J6mAg=='  # noqa: E501

VAULT_MASTER_KEY = 'vault key'
VAULT_V02_CONFIG = 'P7xeh5y4jmjpJ2pFq4KUcTVoaE9ZOEkwWmpVTURSSWQxbGt6emN4aFE4eFM3anVPbDRNTGpOLzY3eDF5aE1YTm5LNWh5Q1BwWTMwM3M5S083MWRWRFlmOXNqSFJNcStGMWFOS3c2emhiOUNNenZYTmNNMnZxaUErdlRoOGF2ZHdGT1ZLNTNLOVJQcU9jWmJrR3g5N09VcVBRZ0ZnSFNUQy9HdFVWWnFteVhRVkY3MHNBdnF2ZWFEbFBseWRGelE1c3BFTnVUckRQdWJSL29wNjFxd2Y2ZVpob3VyVzRod3FKTElTenJ1WTZacTJFOFBtK3BnVzh0QWVxcWtyWFdXOXYyenNQeFNZbWt1MDU2Vm1kVGtISWIxWTBpcWRFbyswUVJudVVhZkVlNVpGWDA4WUQ2Q2JTWW81SnlhQ2Zxa3cxNmZoQjJES0Uyd29rNXpSck5iWVBrVmEwOXFya1NpMi9saU5LL3F0M3N3MjZKekNCem9ER2svWkZ0SUJLdmlHRno0VlQzQ3pqZTBWcTM3YmRiNmJjTkhqUHZoQ0NxMW1ldW1XOFVVK3pQMEtUMkRMVGNvNHFlOG40ck5KcGhsYXg1b1VzZ1NYU1B2T3RXdEkwYzg4NWE3YWUzOWI1MDI0MThhMWZjODQ3MDA2OTJmNDQ0MDkxNGFiNmRlMGQ2YjZiNjI5NGMwN2IwMmI4MGZi'  # noqa: E501
VAULT_V02_CONFIG_DATA = {
    'global': {
        'phrase': DUMMY_PASSPHRASE.rstrip('\n'),
    },
    'services': {
        '(meta)': {
            'notes': 'This config was originally in v0.2 format.',
        },
        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
    },
}
VAULT_V03_CONFIG = 'sBPBrr8BFHPxSJkV/A53zk9zwDQHFxLe6UIusCVvzFQre103pcj5xxmE11lMTA0U2QTYjkhRXKkH5WegSmYpAnzReuRsYZlWWp6N4kkubf+twZ9C3EeggPm7as2Af4TICHVbX4uXpIHeQJf9y1OtqrO+SRBrgPBzgItoxsIxebxVKgyvh1CZQOSkn7BIzt9xKhDng3ubS4hQ91fB0QCumlldTbUl8tj4Xs5JbvsSlUMxRlVzZ0OgAOrSsoWELXmsp6zXFa9K6wIuZa4wQuMLQFHiA64JO1CR3I+rviWCeMlbTOuJNx6vMB5zotKJqA2hIUpN467TQ9vI4g/QTo40m5LT2EQKbIdTvBQAzcV4lOcpr5Lqt4LHED5mKvm/4YfpuuT3I3XCdWfdG5SB7ciiB4Go+xQdddy3zZMiwm1fEwIB8XjFf2cxoJdccLQ2yxf+9diedBP04EsMHrvxKDhQ7/vHl7xF2MMFTDKl3WFd23vvcjpR1JgNAKYprG/e1p/7'  # noqa: E501
VAULT_V03_CONFIG_DATA = {
    'global': {
        'phrase': DUMMY_PASSPHRASE.rstrip('\n'),
    },
    'services': {
        '(meta)': {
            'notes': 'This config was originally in v0.3 format.',
        },
        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
    },
}
VAULT_STOREROOM_CONFIG_ZIPPED = b"""
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
"""
VAULT_STOREROOM_CONFIG_DATA = {
    'global': {
        'phrase': DUMMY_PASSPHRASE.rstrip('\n'),
    },
    'services': {
        '(meta)': {
            'notes': 'This config was originally in storeroom format.',
        },
        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
    },
}

_VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED_JAVASCRIPT_SOURCE = """
// Executed in the top-level directory of the vault project code, in Node.js.
const storeroom = require('storeroom')
const Store = require('./lib/store.js')
let store = new Store(storeroom.createFileAdapter('./broken-dir', 'vault key'))
await store._storeroom.put('/services/array/', ['entry1','entry2'])
// The resulting "broken-dir" was then zipped manually.
"""
VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED = b"""
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
"""

CANNOT_LOAD_CRYPTOGRAPHY = (
    'Cannot load the required Python module "cryptography".'
)

skip_if_no_agent = pytest.mark.skipif(
    not os.environ.get('SSH_AUTH_SOCK'), reason='running SSH agent required'
)
skip_if_cryptography_support = pytest.mark.skipif(
    importlib.util.find_spec('cryptography') is not None,
    reason='cryptography support available; cannot test "no support" scenario',
)
skip_if_no_cryptography_support = pytest.mark.skipif(
    importlib.util.find_spec('cryptography') is None,
    reason='no "cryptography" support',
)


def list_keys(self: Any = None) -> list[_types.KeyCommentPair]:
    del self  # Unused.
    Pair = _types.KeyCommentPair  # noqa: N806
    list1 = [
        Pair(value['public_key_data'], f'{key} test key'.encode('ASCII'))
        for key, value in SUPPORTED_KEYS.items()
    ]
    list2 = [
        Pair(value['public_key_data'], f'{key} test key'.encode('ASCII'))
        for key, value in UNSUITABLE_KEYS.items()
    ]
    return list1 + list2


def list_keys_singleton(self: Any = None) -> list[_types.KeyCommentPair]:
    del self  # Unused.
    Pair = _types.KeyCommentPair  # noqa: N806
    list1 = [
        Pair(value['public_key_data'], f'{key} test key'.encode('ASCII'))
        for key, value in SUPPORTED_KEYS.items()
    ]
    return list1[:1]


def suitable_ssh_keys(conn: Any) -> Iterator[_types.KeyCommentPair]:
    del conn  # Unused.
    Pair = _types.KeyCommentPair  # noqa: N806
    yield from [
        Pair(DUMMY_KEY1, b'no comment'),
        Pair(DUMMY_KEY2, b'a comment'),
    ]


def phrase_from_key(key: bytes) -> bytes:
    if key == DUMMY_KEY1:  # pragma: no branch
        return DUMMY_PHRASE_FROM_KEY1
    raise KeyError(key)  # pragma: no cover


@contextlib.contextmanager
def isolated_config(
    monkeypatch: pytest.MonkeyPatch,
    runner: click.testing.CliRunner,
    config: Any,
) -> Iterator[None]:
    prog_name = cli.PROG_NAME
    env_name = prog_name.replace(' ', '_').upper() + '_PATH'
    with runner.isolated_filesystem():
        monkeypatch.setenv('HOME', os.getcwd())
        monkeypatch.setenv('USERPROFILE', os.getcwd())
        monkeypatch.delenv(env_name, raising=False)
        os.makedirs(os.path.dirname(cli._config_filename()), exist_ok=True)
        with open(cli._config_filename(), 'w', encoding='UTF-8') as outfile:
            json.dump(config, outfile)
        yield


@contextlib.contextmanager
def isolated_vault_exporter_config(
    monkeypatch: pytest.MonkeyPatch,
    runner: click.testing.CliRunner,
    vault_config: str | bytes | None = None,
    vault_key: str | None = None,
) -> Iterator[None]:
    if TYPE_CHECKING:
        chdir = contextlib.chdir
    else:
        try:
            chdir = contextlib.chdir
        except AttributeError:

            @contextlib.contextmanager
            def chdir(newpath: str) -> Iterator[None]:  # pragma: no branch
                oldpath = os.getcwd()
                os.chdir(newpath)
                yield
                os.chdir(oldpath)

    with runner.isolated_filesystem():
        monkeypatch.setenv('HOME', os.getcwd())
        monkeypatch.setenv('USERPROFILE', os.getcwd())
        monkeypatch.delenv('VAULT_PATH', raising=False)
        monkeypatch.delenv('VAULT_KEY', raising=False)
        monkeypatch.delenv('LOGNAME', raising=False)
        monkeypatch.delenv('USER', raising=False)
        monkeypatch.delenv('USERNAME', raising=False)
        if vault_key is not None:
            monkeypatch.setenv('VAULT_KEY', vault_key)
        match vault_config:
            case str():
                with open('.vault', 'w', encoding='UTF-8') as outfile:
                    print(vault_config, file=outfile)
            case bytes():
                os.makedirs('.vault', mode=0o700, exist_ok=True)
                with (
                    chdir('.vault'),
                    tempfile.NamedTemporaryFile(suffix='.zip') as tmpzipfile,
                ):
                    for line in vault_config.splitlines():
                        tmpzipfile.write(base64.standard_b64decode(line))
                    tmpzipfile.flush()
                    tmpzipfile.seek(0, 0)
                    with zipfile.ZipFile(tmpzipfile.file) as zipfileobj:
                        zipfileobj.extractall()
            case None:
                pass
            case _:  # pragma: no cover
                assert_never(vault_config)
        yield


def auto_prompt(*args: Any, **kwargs: Any) -> str:
    del args, kwargs  # Unused.
    return DUMMY_PASSPHRASE


def make_file_readonly(
    pathname: str | bytes | os.PathLike[str],
    /,
    *,
    try_race_free_implementation: bool = True,
) -> None:
    """Mark a file as read-only.

    On POSIX, this entails removing the write permission bits for user,
    group and other, and ensuring the read permission bit for user is
    set.

    Unfortunately, Windows has its own rules: Set exactly(?) the read
    permission bit for user to make the file read-only, and set
    exactly(?) the write permission bit for user to make the file
    read/write; all other permission bit settings are ignored.

    The cross-platform procedure therefore is:

    1. Call `os.stat` on the file, noting the permission bits.
    2. Calculate the new permission bits POSIX-style.
    3. Call `os.chmod` with permission bit `stat.S_IREAD`.
    4. Call `os.chmod` with the correct POSIX-style permissions.

    If the platform supports it, we use a file descriptor instead of
    a path name.  Otherwise, we use the same path name multiple times,
    and are susceptible to race conditions.

    """
    fname: int | str | bytes | os.PathLike[str]
    if try_race_free_implementation and {os.stat, os.chmod} <= os.supports_fd:
        fname = os.open(
            pathname,
            os.O_RDONLY
            | getattr(os, 'O_CLOEXEC', 0)
            | getattr(os, 'O_NOCTTY', 0),
        )
    else:
        fname = pathname
    try:
        orig_mode = os.stat(fname).st_mode
        new_mode = (
            orig_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH
            | stat.S_IREAD
        )
        os.chmod(fname, stat.S_IREAD)
        os.chmod(fname, new_mode)
    finally:
        if isinstance(fname, int):
            os.close(fname)


class ReadableResult(NamedTuple):
    """Helper class for formatting and testing click.testing.Result objects."""

    exception: BaseException | None
    exit_code: int
    output: str
    stderr: str

    @classmethod
    def parse(cls, r: click.testing.Result, /) -> Self:
        try:
            stderr = r.stderr
        except ValueError:
            stderr = r.output
        return cls(r.exception, r.exit_code, r.output or '', stderr or '')

    def clean_exit(
        self, *, output: str = '', empty_stderr: bool = False
    ) -> bool:
        """Return whether the invocation exited cleanly.

        Args:
            output:
                An expected output string.

        """
        return (
            (
                not self.exception
                or (
                    isinstance(self.exception, SystemExit)
                    and self.exit_code == 0
                )
            )
            and (not output or output in self.output)
            and (not empty_stderr or not self.stderr)
        )

    def error_exit(
        self, *, error: str | type[BaseException] = BaseException
    ) -> bool:
        """Return whether the invocation exited uncleanly.

        Args:
            error:
                An expected error message, or an expected numeric error
                code, or an expected exception type.

        """
        match error:
            case str():
                return (
                    isinstance(self.exception, SystemExit)
                    and self.exit_code > 0
                    and (not error or error in self.stderr)
                )
            case _:
                return isinstance(self.exception, error)
