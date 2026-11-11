"""Offline stdlib checks of the production relay's bounded Safe recovery ABI.

Run: PYTHONDONTWRITEBYTECODE=1 python3 web/registration/tests/safe-recovery-relay-test.py
Synthetic ABI inputs prove admission only, not chain state or signature validity.
"""
import importlib.util
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("relay", Path(__file__).resolve().parents[1] / "serve.py")
assert SPEC is not None and SPEC.loader is not None
relay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(relay)

SAFE = "0x" + "11" * 20
RECIPIENT = "0x" + "22" * 20
READS = ("0xffa1ad74", "0xa0e67e2b", "0xe75235b8", "0xaffed0e0")


def rpc(data, to: object = SAFE, block: object = "0x10"):
    return {"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"to": to, "data": data}, block]}


def accepted(request):
    return relay.validate_rpc(json.dumps(request)) is not None


def word(value):
    return f"{value:064x}"


def hash_call(**changes):
    # getTransactionHash(to,value,data,operation,safeTxGas,baseGas,gasPrice,gasToken,refundReceiver,nonce)
    fields = dict(to="00" * 12 + RECIPIENT[2:], value=word(123), offset=word(320), operation=word(0),
                  safeTxGas=word(456), baseGas=word(789), gasPrice=word(0), gasToken=word(0),
                  refundReceiver=word(0), nonce=word(42), length=word(0))
    fields.update(changes)
    return "0xd8d11f78" + "".join(fields.values())


def signature_call(digest="ab" * 32, offset=64, length=96, inner="11" * 96):
    return "0x1626ba7e" + digest + word(offset) + word(length) + inner


class SafeRecoveryRelayTests(unittest.TestCase):
    def test_canonical_no_argument_reads(self):
        for data in READS:
            for block in ("0x10", "latest"):
                with self.subTest(data=data, block=block):
                    self.assertTrue(accepted(rpc(data, block=block)))
            with self.subTest(data=data, case="uppercase"):
                self.assertTrue(accepted(rpc("0x" + data[2:].upper())))

    def test_no_argument_reads_reject_noncanonical_shapes(self):
        for data in READS:
            for malformed in (data + "00", data + "00" * 32, data + "\n", data[:-2], data + "0", data + "gg"):
                with self.subTest(data=malformed):
                    self.assertFalse(accepted(rpc(malformed)))

    def test_native_transaction_hash_complete_abi(self):
        for data in (hash_call(), hash_call(value=word(0), safeTxGas=word(0), baseGas=word(0), nonce=word(0)),
                     hash_call(value=word(2**256 - 1), safeTxGas=word(2**256 - 1),
                               baseGas=word(2**256 - 1), nonce=word(2**256 - 1))):
            for encoded in (data, "0x" + data[2:].upper()):
                with self.subTest(data=encoded):
                    self.assertTrue(accepted(rpc(encoded)))

    def test_transaction_hash_rejects_other_operations_and_reimbursement(self):
        for field in ("operation", "gasPrice", "gasToken", "refundReceiver"):
            for value in (1, 2, 255, 256, 2**256 - 1):
                with self.subTest(field=field, value=value):
                    self.assertFalse(accepted(rpc(hash_call(**{field: word(value)}))))

    def test_transaction_hash_rejects_noncanonical_native_recipient(self):
        for address in (word(0), "01" + "00" * 11 + RECIPIENT[2:], "00" * 12 + SAFE[2:]):
            with self.subTest(address=address):
                self.assertFalse(accepted(rpc(hash_call(to=address))))

    def test_transaction_hash_rejects_dynamic_payloads_offsets_and_trailing_bytes(self):
        for offset in (0, 32, 288, 319, 321, 352, 2**256 - 1):
            with self.subTest(offset=offset):
                self.assertFalse(accepted(rpc(hash_call(offset=word(offset)))))
        for length in (1, 31, 32, 33, 96, 2**256 - 1):
            for tail in ("", "00" * 32, "a9059cbb" + "00" * 28):
                with self.subTest(length=length, tail=tail):
                    self.assertFalse(accepted(rpc(hash_call(length=word(length)) + tail)))
        data = hash_call()
        for malformed in (data[:-2], data[:-64], data + "00", data + word(0), data + "\n", data + "0",
                          data[:10] + "gg" + data[12:]):
            with self.subTest(data=malformed):
                self.assertFalse(accepted(rpc(malformed)))

    def test_erc1271_exact_96_byte_inner_signature(self):
        for digest, inner in (("ab" * 32, "11" * 96), ("00" * 32, "00" * 96), ("ff" * 32, "ff" * 96)):
            data = signature_call(digest=digest, inner=inner)
            for encoded in (data, "0x" + data[2:].upper()):
                with self.subTest(digest=digest, inner=inner):
                    self.assertTrue(accepted(rpc(encoded)))

    def test_erc1271_rejects_other_offsets_lengths_padding_and_outer_signature(self):
        for offset in (0, 32, 63, 65, 96, 2**256 - 1):
            with self.subTest(offset=offset):
                self.assertFalse(accepted(rpc(signature_call(offset=offset))))
        for length in (0, 1, 64, 65, 95, 97, 161, 2**256 - 1):
            for inner in ("11" * 96, "11" * min(length, 161), "11" * min(length, 161) + "00" * 31):
                with self.subTest(length=length, inner=inner):
                    self.assertFalse(accepted(rpc(signature_call(length=length, inner=inner))))
        data = signature_call()
        for malformed in (data[:-2], data[:-64], data + "00", data + word(0), data + "\n", data + "0",
                          signature_call(digest="ab" * 31), signature_call(digest="ab" * 33),
                          signature_call(inner="11" * 95), signature_call(inner="11" * 97),
                          signature_call(inner="gg" + "11" * 95)):
            with self.subTest(data=malformed):
                self.assertFalse(accepted(rpc(malformed)))

    def test_recovery_calls_do_not_admit_generic_call_envelopes_or_writes(self):
        for data in (*READS, hash_call(), signature_call()):
            for name, value in (("from", RECIPIENT), ("value", "0x0"), ("gas", "0x1"),
                                ("gasPrice", "0x0"), ("input", data), ("nonce", "0x0")):
                request = rpc(data)
                request["params"][0][name] = value
                with self.subTest(selector=data[:10], extra=name):
                    self.assertFalse(accepted(request))
            for to in (SAFE + "\n", SAFE[:-2], "0x" + "gg" * 20, None, 123):
                with self.subTest(selector=data[:10], to=to):
                    self.assertFalse(accepted(rpc(data, to=to)))
            for block in ("pending", "0x00", "0x10\n", {}, None, 16):
                with self.subTest(selector=data[:10], block=block):
                    self.assertFalse(accepted(rpc(data, block=block)))
            for method in ("eth_sendTransaction", "eth_estimateGas", "eth_sign", "debug_traceCall"):
                request = rpc(data)
                request["method"] = method
                with self.subTest(selector=data[:10], method=method):
                    self.assertFalse(accepted(request))
        for data in ("0x", "0xdeadbeef", "0xa9059cbb" + word(0) * 2, "0x20c13b0b" + word(0) * 3,
                     "0x6a761202" + hash_call()[10:]):
            with self.subTest(data=data):
                self.assertFalse(accepted(rpc(data)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
