# SPDX-License-Identifier: MIT
import unittest
import copy
import json
from pathlib import Path
from fractions import Fraction
import legality193 as l
import audit_legality193 as a


class SourceLegality(unittest.TestCase):
    def test_mask_is_a_source_with_eew_one(self):
        self.assertEqual(l.source_conflicts([(0, 1, 1), (0, 1, 8)]),
                         [dict(reg=0, first_eew=1, second_eew=8)])

    def test_equal_width_alias_and_mask_logic_are_legal(self):
        self.assertFalse(l.source_conflicts([(8, 2, 32), (8, 2, 32)]))
        self.assertFalse(l.source_conflicts([(0, 1, 1), (0, 1, 1)]))

    def test_fractional_operand_still_shares_register(self):
        self.assertTrue(l.source_conflicts([(8, 1, 8), (8, 1, 16)]))

    def test_high_part_alias_is_reserved_for_two_sources(self):
        self.assertEqual(l.source_conflicts([(8, 2, 64), (9, 1, 32)]),
                         [dict(reg=9, first_eew=64, second_eew=32)])
        self.assertFalse(l.source_conflicts([(8, 2, 64), (10, 1, 32)]))

    def test_segment_field_not_only_first_base(self):
        c = dict(family='indexed166', store=True, nf=2, vd=8,
                 group_registers=1, eew=8, mask='none', vs2=9,
                 index_registers=1, index_eew=16)
        self.assertFalse(l.ordinary_credit(c))
        c['vs2'] = 10
        self.assertTrue(l.ordinary_credit(c))

    def test_mask_store_special_form_has_no_execution_mask_source(self):
        # vsm.v is encoded vm=1 and its only vector source is a mask, EEW=1.
        self.assertFalse(l.source_conflicts([(0, 1, 1)]))

    def test_existing_masked_store_changes_credit_not_required_trap(self):
        c = dict(family='memory165', store=True, nf=1, vd=0,
                 group_registers=1, eew=8, mask='alternating')
        self.assertFalse(l.ordinary_credit(c))
        self.assertTrue(l.ordinary_credit(c, 'public-review-3570f998'))
        c['vd'] = 8
        self.assertTrue(l.ordinary_credit(c))

    def test_compress_mask_data_source_alias(self):
        c = dict(family='permute162', mnemonic='vcompress', vs1=16,
                 vs2=16, group_registers=1, sew=8, mask='none')
        self.assertFalse(l.ordinary_credit(c))
        c['vs1'] = 0
        self.assertTrue(l.ordinary_credit(c))

    def test_mandatory_fractional_profile(self):
        pairs = l.mandatory_vtypes()
        self.assertEqual(len(pairs), 22)
        self.assertIn((8, Fraction(1, 8)), pairs)
        self.assertIn((16, Fraction(1, 4)), pairs)
        self.assertIn((32, Fraction(1, 2)), pairs)
        self.assertNotIn((64, Fraction(1, 2)), pairs)

    def test_bad_extent_and_baseline_fail_closed(self):
        for operands in [[(31, 2, 8)], [(0, 0, 1)], [(32, 1, 1)]]:
            with self.assertRaises(ValueError):
                l.source_conflicts(operands)
        with self.assertRaises(ValueError):
            l.ordinary_credit({}, 'unstated')

    def test_actual_final181_bounded_selection(self):
        capture = json.loads((Path(__file__).resolve().parents[3] /
            'docs/rvv-validation/legality-task193/DECLARATIONS-fixed.json').read_text())
        result = a.audit(capture)
        self.assertEqual((result['reserved_excluded'], result['legal_included']), (86, 86))
        for accepted in (False, True):
            bad = copy.deepcopy(capture)
            row = next(r for r in bad['records'] if r['accepted'] == accepted)
            row['accepted'] = not accepted
            with self.assertRaises(AssertionError):
                a.audit(bad)

    def test_audit_rejects_geometry_corruption(self):
        capture = json.loads((Path(__file__).resolve().parents[3] /
            'docs/rvv-validation/legality-task193/DECLARATIONS-fixed.json').read_text())
        for family, field, replacement in [('memory165', 'vd', 8),
                                            ('permute162', 'vs1', 0)]:
            bad = copy.deepcopy(capture)
            row = next(r for r in bad['records'] if r['case']['family'] == family
                       and not r['accepted'])
            row['case'][field] = replacement
            with self.assertRaises(AssertionError):
                a.audit(bad)


if __name__ == '__main__':
    unittest.main()
