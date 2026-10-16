"""Diagnostic-receipt controls only; no synthetic ISA oracle or guest execution."""
import unittest

from audit_rvv_external_admission import require_single_execution, target_frame


TEXT = '''RVV_RUN_FORM entry=000125bc end=000125c8 boundary=00013000 members=3 ops=falu,falu,falu
RVV_DIRECT enabled=1 hit_counter=1 inline_hits=41 guard_fallbacks=34
RVV_RUN_FRAME 000125a0,0,3,4,1
RVV_RUN_FRAME 000125a0,1,4,4,1
'''


class AdmissionReceiptTests(unittest.TestCase):
    def test_global_fallbacks_preserved_not_target_failure(self):
        form, frame, fallbacks = target_frame(TEXT)
        self.assertEqual(form[:2], ('000125bc', '000125c8'))
        self.assertEqual(frame, ('000125a0', '0', '3', '4', '1'))
        self.assertEqual(fallbacks, 34)
        require_single_execution(int(frame[-1]), 1)

    def test_missing_form_or_frame_rejected(self):
        for prefix in ('RVV_RUN_FORM ', 'RVV_RUN_FRAME '):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                target_frame('\n'.join(line for line in TEXT.splitlines() if not line.startswith(prefix)))

    def test_missing_or_duplicate_global_receipt_rejected(self):
        counter = next(line for line in TEXT.splitlines() if line.startswith('RVV_DIRECT '))
        for text in (TEXT.replace(counter, ''), TEXT + counter + '\n'):
            with self.assertRaises(ValueError):
                target_frame(text)

    def test_duplicate_target_receipt_rejected(self):
        with self.assertRaises(ValueError):
            target_frame(TEXT + 'RVV_RUN_FRAME 000125a0,0,3,4,1\n')

    def test_absent_or_repeated_native_execution_rejected(self):
        for count in (0, 2):
            with self.subTest(count=count), self.assertRaises(ValueError):
                require_single_execution(count, 1)

    def test_absent_or_repeated_tb_execution_rejected(self):
        for count in (0, 2):
            with self.subTest(count=count), self.assertRaises(ValueError):
                require_single_execution(1, count)


if __name__ == '__main__':
    unittest.main()
