"""Structural checks for off-scope score preservation and scoped inference."""

import math
import unittest
import numpy as np

from train_canonical import compose, validate_inputs


def tree(threshold, left, right):
    return dict(feature_idx=[0,-1,-1],threshold=[threshold,0.,0.],left=[1,0,0],
                right=[2,0,0],value=[0.,left,right],missing_left=[1,0,0],is_leaf=[0,1,1])


def score(model, features):
    value=model["baseline"]
    for t in model["trees"]:
        n=0
        while not t["is_leaf"][n]:
            x=features[t["feature_idx"][n]]
            go_left=t["missing_left"][n] if math.isnan(x) else x<=t["threshold"][n]
            n=t["left"][n] if go_left else t["right"][n]
        value+=t["value"][n]
    return value


class CompositionTests(unittest.TestCase):
    def test_invalid_parser_facts_and_labels_are_rejected(self):
        names = ["x", "ctx_parser_literal_sensitive_v1", "ctx_ui_namespace_v1"]
        validate_inputs([{"label_binary": 1}], np.array([[.3, 1., 0.]]), names)
        for x, label in [([.3, .7, 0.], 1), ([.3, 1., float("nan")], 1), ([.3, 1., 0.], 2)]:
            with self.assertRaises(ValueError):
                validate_inputs([{"label_binary": label}], np.array([x]), names)

    def test_off_scope_logits_remain_identical_and_proof_selects_calibration(self):
        base=dict(baseline=.12,feature_names=["x"],trees=[tree(.5,-.7,.9),tree(2.,.5,-.8)])
        names=["x","ctx_parser_literal_sensitive_v1","ctx_ui_namespace_v1"]
        calibration=dict(baseline=-.23,feature_names=names,trees=[tree(1.,.3,-.4)])
        model=compose(base,calibration,names)
        for x in [-100.,0.,.5,.501,1.,2.,100.]:
            for ui in [0.,1.]:
                self.assertEqual(score(model,[x,0.,ui]),score(base,[x]))
                self.assertAlmostEqual(score(model,[x,1.,ui]),score(calibration,[x,1.,ui]),places=14)
                self.assertEqual(score(model,[x,float('nan'),ui]),score(base,[x]))

    def test_reordered_base_features_are_rejected(self):
        base=dict(baseline=0.,feature_names=["x"],trees=[tree(1.,0.,1.)])
        names=["wrong","ctx_parser_literal_sensitive_v1","ctx_ui_namespace_v1"]
        calibration=dict(base,feature_names=names)
        with self.assertRaises(ValueError):
            compose(base,calibration,names)


if __name__=='__main__':
    unittest.main()
