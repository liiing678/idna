"""Tests for the machine-readable attributes carried by IDNAError."""

import codecs
import pickle
import re
import unittest
from typing import get_args
from unittest import mock

import idna
import idna.codec
import idna.core


class ErrorAttributeTests(unittest.TestCase):
    def _cases(self):
        """(trigger, expected class, expected text, codepoint, position)"""
        r = "\u05d0"  # R
        an = "\u0660"  # AN
        nsm = "\u0610"  # NSM
        return [
            (lambda: idna.alabel("abc\u0141"), idna.InvalidCodepoint, "abc\u0141", 0x141, 4),
            (lambda: idna.alabel("a\u200cb"), idna.InvalidCodepointContext, "a\u200cb", 0x200C, 2),
            (lambda: idna.alabel("a\xb7b"), idna.InvalidCodepointContext, "a\xb7b", 0xB7, 2),
            (lambda: idna.alabel("\u0301abc"), idna.IDNAError, "\u0301abc", 0x301, 1),
            (lambda: self._unknown_direction("ab"), idna.IDNABidiError, "ab", 0x61, 1),
            (lambda: idna.check_bidi(an + r), idna.IDNABidiError, an + r, 0x660, 1),  # rule 1
            (lambda: idna.check_bidi(r + "a"), idna.IDNABidiError, r + "a", 0x61, 2),  # rule 2
            (lambda: idna.check_bidi(r + "-" + nsm), idna.IDNABidiError, r + "-" + nsm, 0x2D, 2),  # rule 3
            (lambda: idna.check_bidi(r + an + "0"), idna.IDNABidiError, r + an + "0", 0x30, 3),  # rule 4
            (lambda: idna.alabel("a" + r), idna.IDNABidiError, "a" + r, 0x5D0, 2),  # rule 5
            (lambda: idna.check_bidi("a-", check_ltr=True), idna.IDNABidiError, "a-", 0x2D, 2),  # rule 6
            (lambda: idna.uts46_remap("a\x80"), idna.InvalidCodepoint, "a\x80", 0x80, 2),
            (lambda: idna.uts46_remap("a_b"), idna.InvalidCodepoint, "a_b", 0x5F, 2),
            (lambda: idna.uts46_remap("a\uff3fb"), idna.InvalidCodepoint, "a\uff3fb", 0xFF3F, 2),
            (lambda: idna.encode("a_b", uts46=True, std3_rules=True), idna.InvalidCodepoint, "a_b", 0x5F, 2),
        ]

    def test_attributes_are_populated(self):
        for trigger, exc_class, text, codepoint, position in self._cases():
            with self.subTest(text=text):
                with self.assertRaises(exc_class) as ctx:
                    trigger()
                err = ctx.exception
                self.assertEqual(err.text, text)
                self.assertEqual(err.codepoint, codepoint)
                self.assertEqual(err.position, position)
                # position indexes text and names the codepoint ...
                self.assertEqual(ord(err.text[err.position - 1]), err.codepoint)
                # ... and agrees with the message where the message quotes one
                match = re.search(r"position (\d+)", str(err))
                if match:
                    self.assertEqual(int(match.group(1)), err.position)

    def test_every_error_code_is_raisable(self):
        """Each code has an input that produces it, and vice versa."""
        r = "\u05d0"
        an = "\u0660"
        triggers = {
            "input_too_long": lambda: idna.encode("a" * 1025),
            "label_too_long": lambda: idna.alabel("a" * 64),
            "domain_too_long": lambda: idna.encode(".".join(["a" * 63] * 4)),
            "empty_label": lambda: idna.encode("a..b"),
            "empty_domain": lambda: idna.encode(""),
            "not_nfc": lambda: idna.alabel("e\u0301xample"),
            "hyphen_3_4": lambda: idna.alabel("ab--cd"),
            "hyphen_start_end": lambda: idna.alabel("-abc"),
            "leading_combiner": lambda: idna.alabel("\u0301abc"),
            "disallowed_codepoint": lambda: idna.alabel("abc\u0141"),
            "contextj": lambda: idna.alabel("a\u200cb"),
            "contexto": lambda: idna.alabel("a\xb7b"),
            "unknown_codepoint": self._unknown_codepoint,
            "bidi_rule_1": lambda: idna.check_bidi(an + r),
            "bidi_rule_2": lambda: idna.check_bidi(r + "a"),
            "bidi_rule_3": lambda: idna.check_bidi(r + "-"),
            "bidi_rule_4": lambda: idna.check_bidi(r + an + "0"),
            "bidi_rule_5": lambda: idna.alabel("a" + r),
            "bidi_rule_6": lambda: idna.check_bidi("a-", check_ltr=True),
            "bidi_unknown_direction": lambda: self._unknown_direction("ab"),
            "invalid_alabel": lambda: idna.ulabel("xn--"),
            "non_canonical_alabel": lambda: idna.ulabel("xn---bbk"),
            "invalid_ascii": lambda: idna.encode(b"\xff"),
            "invalid_utf8": lambda: idna.check_label(b"\xff"),
            "uts46_disallowed": lambda: idna.uts46_remap("a\x80"),
            "uts46_std3": lambda: idna.uts46_remap("a_b"),
            "unsupported_errors": lambda: codecs.encode("a", "idna2008", errors="ignore"),
        }
        codes = set(get_args(idna.core._ErrorCode))
        self.assertEqual(set(triggers), codes)
        for code, trigger in triggers.items():
            with self.subTest(code=code):
                with self.assertRaises(idna.IDNAError) as ctx:
                    trigger()
                self.assertEqual(ctx.exception.code, code)

    # Conditions that depend on the host's Unicode database being older than
    # the input cannot be triggered portably (from Python 3.15,
    # ``unicodedata.bidirectional`` returns a default class for every
    # codepoint), so simulate them.
    def _unknown_codepoint(self):
        with mock.patch("idna.core._combining_class", side_effect=ValueError):
            idna.check_label("a\u200cb")

    def _unknown_direction(self, label):
        with mock.patch("idna.core.unicodedata.bidirectional", return_value=""):
            idna.check_bidi(label)

    def test_unknown_codepoint_adjacent_to_joiner(self):
        unknown = mock.patch("idna.core._combining_class", side_effect=ValueError)
        with unknown, self.assertRaises(idna.IDNAError) as ctx:
            idna.check_label("a\u200cb")
        err = ctx.exception
        self.assertNotIsInstance(err, idna.InvalidCodepointContext)
        self.assertEqual(err.code, "unknown_codepoint")
        self.assertEqual((err.text, err.codepoint, err.position), ("a\u200cb", 0x200C, 2))

    def test_positional_attributes_default_to_none(self):
        for trigger in (
            lambda: idna.encode("a..b"),
            lambda: idna.encode(""),
            lambda: idna.alabel("a" * 64),
            lambda: idna.alabel("ab--cd"),
            lambda: idna.alabel("-abc"),
            lambda: idna.ulabel("xn--"),
            lambda: idna.encode(b"\xff"),
        ):
            with self.assertRaises(idna.IDNAError) as ctx:
                trigger()
            err = ctx.exception
            self.assertIsNotNone(err.code)
            self.assertIsNone(err.text)
            self.assertIsNone(err.codepoint)
            self.assertIsNone(err.position)

    def test_construction_is_backwards_compatible(self):
        err = idna.IDNAError("just a message")
        self.assertEqual(str(err), "just a message")
        self.assertEqual(err.args, ("just a message",))
        self.assertIsNone(err.code)
        self.assertIsNone(err.text)
        self.assertEqual(idna.IDNAError().args, ())
        self.assertEqual(idna.InvalidCodepoint("a", "b").args, ("a", "b"))

    def test_message_remains_sole_positional_argument(self):
        with self.assertRaises(idna.InvalidCodepoint) as ctx:
            idna.alabel("abc\u0141")
        self.assertEqual(ctx.exception.args, ("Codepoint U+0141 at position 4 of 'abc\u0141' not allowed",))

    def test_attributes_survive_pickle(self):
        with self.assertRaises(idna.InvalidCodepoint) as ctx:
            idna.alabel("abc\u0141")
        err = pickle.loads(pickle.dumps(ctx.exception))
        self.assertIsInstance(err, idna.InvalidCodepoint)
        self.assertEqual(str(err), str(ctx.exception))
        self.assertEqual(err.code, "disallowed_codepoint")
        self.assertEqual((err.text, err.codepoint, err.position), ("abc\u0141", 0x141, 4))


class OverlongInputErrorTests(unittest.TestCase):
    """超长标签/域名抛出的异常类型与 code。"""

    def test_overlong_label_is_plain_idnaerror(self):
        # 63 字节上限：ASCII 超 64 字符，或 Punycode 展开后超 63 字节，
        # 抛的都是 IDNAError 本身，不是 InvalidCodepoint 等子类。
        for label in ("a" * 64, "中" * 58):
            with self.subTest(label=label[:4]):
                with self.assertRaises(idna.IDNAError) as ctx:
                    idna.alabel(label)
                err = ctx.exception
                self.assertIs(type(err), idna.IDNAError)
                self.assertEqual(err.code, "label_too_long")
        # 恰好 63 字节的 A-label 合法。
        self.assertEqual(idna.alabel("中" * 57), b"xn--fiq" + b"a" * 56)

    def test_check_label_uses_domain_length_bound(self):
        # check_label 自身按 254 字符（域名上限）截断，不是 63 字节；
        # 63 字节的标签限制是 alabel 在 Punycode 编码之后才检查的。
        idna.check_label("é" * 100)
        idna.check_label("é" * 254)
        with self.assertRaises(idna.IDNAError) as ctx:
            idna.check_label("é" * 255)
        self.assertEqual(ctx.exception.code, "label_too_long")

    def test_overlong_domain_and_input(self):
        with self.assertRaises(idna.IDNAError) as ctx:
            idna.encode(".".join(["a" * 63] * 4))
        self.assertEqual(ctx.exception.code, "domain_too_long")
        with self.assertRaises(idna.IDNAError) as ctx:
            idna.encode("a" * 1025)
        self.assertEqual(ctx.exception.code, "input_too_long")


class MixedScriptErrorTests(unittest.TestCase):
    """混合脚本输入的报错类型——网关按异常类型降级时以这里为准。"""

    def test_exception_hierarchy(self):
        # 降级逻辑注意：三个具体异常都是 IDNAError 的子类，彼此之间
        # 没有继承关系；用 isinstance 分类时子类必须先于 IDNAError 判断。
        for cls in (idna.IDNABidiError, idna.InvalidCodepoint, idna.InvalidCodepointContext):
            self.assertTrue(issubclass(cls, idna.IDNAError))
        self.assertFalse(issubclass(idna.IDNABidiError, idna.InvalidCodepoint))
        self.assertFalse(issubclass(idna.InvalidCodepointContext, idna.InvalidCodepoint))
        self.assertFalse(issubclass(idna.InvalidCodepoint, idna.InvalidCodepointContext))

    def test_latin_plus_rtl_is_bidi_error(self):
        # 拉丁混希伯来：不是“非法码位”，而是 Bidi Rule 冲突。
        with self.assertRaises(idna.IDNABidiError) as ctx:
            idna.alabel("a\u05d0")
        self.assertEqual(ctx.exception.code, "bidi_rule_5")
        with self.assertRaises(idna.IDNABidiError) as ctx:
            idna.alabel("\u05d0a")
        self.assertEqual(ctx.exception.code, "bidi_rule_2")

    def test_greek_plus_cyrillic_is_valid(self):
        # 反直觉但正确：IDNA 2008 不检查“混脚本”本身，希腊+西里尔合法。
        # 网关此前把这类输入预期为 InvalidCodepoint——是预期写错了。
        self.assertEqual(idna.alabel("αб"), b"xn--mxa0x")

    def test_mixed_arabic_digit_families_is_contexto(self):
        # 阿拉伯-印度数字与扩展阿拉伯-印度数字混用 → CONTEXTO 规则。
        with self.assertRaises(idna.InvalidCodepointContext) as ctx:
            idna.alabel("\u0661\u06f2")
        self.assertEqual(ctx.exception.code, "contexto")

    def test_joiner_between_latin_is_contextj(self):
        with self.assertRaises(idna.InvalidCodepointContext) as ctx:
            idna.alabel("a\u200cb")
        self.assertEqual(ctx.exception.code, "contextj")

    def test_disallowed_codepoint(self):
        with self.assertRaises(idna.InvalidCodepoint) as ctx:
            idna.alabel("abc\u0141")
        self.assertEqual(ctx.exception.code, "disallowed_codepoint")

    def test_exact_type_per_trigger(self):
        # 每类输入只落一种异常类型，且类型精确（不是其子类/父类）。
        triggers = [
            (lambda: idna.alabel("a" * 64), idna.IDNAError),
            (lambda: idna.alabel("a\u05d0"), idna.IDNABidiError),
            (lambda: idna.alabel("a\u200cb"), idna.InvalidCodepointContext),
            (lambda: idna.alabel("\u0661\u06f2"), idna.InvalidCodepointContext),
            (lambda: idna.alabel("abc\u0141"), idna.InvalidCodepoint),
        ]
        for trigger, exact in triggers:
            with self.subTest(exact=exact.__name__):
                with self.assertRaises(idna.IDNAError) as ctx:
                    trigger()
                self.assertIs(type(ctx.exception), exact)


if __name__ == "__main__":
    unittest.main()
