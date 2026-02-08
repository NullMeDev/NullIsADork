"""
MadyDorker v3.14 — ML False Positive Filter

Machine-learning-based classifier to reduce false positives in:
- SQLi detection results
- Secret extraction results
- Key validation results

Uses a lightweight gradient-boosted decision tree (or logistic regression
fallback) trained on feature vectors extracted from scan results.

Features extracted:
- Response similarity (original vs injected)
- Error pattern diversity
- Parameter behavior consistency
- WAF detection correlation
- Injection type confidence
- DBMS fingerprint strength
- Response time anomalies
- Content-length variance
- Reflection patterns
- Historical accuracy per domain

No external ML libraries required — implements decision tree from scratch.
Falls back to rule-based scoring if training data insufficient.
"""

import hashlib
import json
import logging
import math
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("ml_filter")


# ═══════════════════════════════════════════════════════════════
#   DATA CLASSES
# ═══════════════════════════════════════════════════════════════

@dataclass
class FilterResult:
    """ML filter verdict on a finding."""
    url: str
    finding_type: str       # "sqli", "secret", "key"
    is_positive: bool       # True = likely real, False = likely false positive
    confidence: float       # 0.0 - 1.0
    score: float            # Raw model score (higher = more real)
    features: Dict[str, float] = field(default_factory=dict)
    reason: str = ""        # Human-readable explanation


@dataclass
class TrainingSample:
    """A labeled sample for training."""
    features: Dict[str, float]
    label: int  # 1 = true positive, 0 = false positive
    weight: float = 1.0


# ═══════════════════════════════════════════════════════════════
#   FEATURE EXTRACTION
# ═══════════════════════════════════════════════════════════════

class FeatureExtractor:
    """Extracts numerical feature vectors from scan results."""

    # Feature definitions with their default values
    SQLI_FEATURES = [
        "response_diff_ratio",      # How much response changed with injection
        "error_pattern_count",      # Number of distinct error patterns matched
        "dbms_confidence",          # DBMS fingerprint confidence
        "injection_type_score",     # union=1.0, boolean=0.7, time=0.5, error=0.8
        "column_count_detected",    # Binary: was column count found
        "injectable_columns",       # Number of injectable columns
        "waf_detected",            # Binary: is WAF present
        "response_time_ratio",     # Injected/normal response time
        "content_length_diff",     # Normalized content length difference
        "reflection_count",        # Number of payload reflections
        "param_count",             # Number of parameters in URL
        "https_score",             # HTTPS = 1.0, HTTP = 0.5
        "has_db_version",          # Binary: did we extract DB version
        "has_current_db",          # Binary: did we extract current DB
        "has_current_user",        # Binary: did we extract current user
        "data_extracted",          # Binary: any data rows extracted
        "dios_success",            # Binary: DIOS worked
        "domain_history_score",    # Historical true positive rate for this domain
    ]

    SECRET_FEATURES = [
        "pattern_specificity",     # How specific the regex pattern is (entropy)
        "context_score",           # Surrounding code context relevance
        "key_length",              # Normalized key length
        "entropy",                 # Shannon entropy of the key value
        "has_prefix",              # Known prefix (sk_live_, AKIA, etc.)
        "in_config_file",          # Found in config/env file
        "in_html_comment",         # Found in HTML comment
        "in_javascript",           # Found in JS code
        "duplicate_count",         # Times seen across pages
        "live_validation_score",   # Result from key_validator (1.0 = live)
    ]

    @staticmethod
    def extract_sqli_features(
        sqli_result: Any,
        original_response: str = "",
        injected_response: str = "",
        response_time_normal: float = 0.0,
        response_time_injected: float = 0.0,
        waf_detected: bool = False,
        domain_history: float = 0.5,
    ) -> Dict[str, float]:
        """Extract features from an SQLi scan result."""
        features = {}

        # Response diff ratio
        if original_response and injected_response:
            common = sum(
                1 for a, b in zip(original_response[:5000], injected_response[:5000])
                if a == b
            )
            max_len = max(len(original_response[:5000]), len(injected_response[:5000]), 1)
            features["response_diff_ratio"] = 1.0 - (common / max_len)
        else:
            features["response_diff_ratio"] = 0.5

        # Error pattern count
        error_count = 0
        if hasattr(sqli_result, "errors") and sqli_result.errors:
            error_count = len(sqli_result.errors) if isinstance(sqli_result.errors, list) else 1
        features["error_pattern_count"] = min(error_count / 5.0, 1.0)

        # DBMS confidence
        dbms = getattr(sqli_result, "dbms", "")
        features["dbms_confidence"] = 1.0 if dbms else 0.0

        # Injection type score
        inj_type = getattr(sqli_result, "injection_type", "")
        type_scores = {
            "union": 1.0, "error": 0.8, "boolean": 0.7,
            "time": 0.5, "blind": 0.6,
        }
        features["injection_type_score"] = type_scores.get(inj_type, 0.3)

        # Column count
        col_count = getattr(sqli_result, "column_count", 0)
        features["column_count_detected"] = 1.0 if col_count > 0 else 0.0

        # Injectable columns
        inj_cols = getattr(sqli_result, "injectable_columns", [])
        features["injectable_columns"] = min(len(inj_cols) / 5.0, 1.0) if inj_cols else 0.0

        # WAF
        features["waf_detected"] = 1.0 if waf_detected else 0.0

        # Response time ratio
        if response_time_normal > 0 and response_time_injected > 0:
            features["response_time_ratio"] = min(
                response_time_injected / response_time_normal, 5.0
            ) / 5.0
        else:
            features["response_time_ratio"] = 0.5

        # Content length diff
        len_orig = len(original_response) if original_response else 0
        len_inj = len(injected_response) if injected_response else 0
        if len_orig > 0:
            features["content_length_diff"] = min(
                abs(len_inj - len_orig) / max(len_orig, 1), 2.0
            ) / 2.0
        else:
            features["content_length_diff"] = 0.5

        # Reflection count
        reflection = 0
        if injected_response and hasattr(sqli_result, "payload"):
            payload = getattr(sqli_result, "payload", "")
            if payload and payload in injected_response:
                reflection = injected_response.count(payload)
        features["reflection_count"] = min(reflection / 3.0, 1.0)

        # URL params
        url = getattr(sqli_result, "url", "")
        features["param_count"] = min(url.count("&") + 1, 10) / 10.0 if "?" in url else 0.0

        # HTTPS
        features["https_score"] = 1.0 if url.startswith("https://") else 0.5

        # Extracted data signals
        features["has_db_version"] = 1.0 if getattr(sqli_result, "db_version", "") else 0.0
        features["has_current_db"] = 1.0 if getattr(sqli_result, "current_db", "") else 0.0
        features["has_current_user"] = 1.0 if getattr(sqli_result, "current_user", "") else 0.0
        features["data_extracted"] = 1.0 if getattr(sqli_result, "data_extracted", False) else 0.0
        features["dios_success"] = 1.0 if getattr(sqli_result, "dios_success", False) else 0.0

        # Domain history
        features["domain_history_score"] = domain_history

        return features

    @staticmethod
    def extract_secret_features(
        secret_match: Dict[str, Any],
        page_content: str = "",
        live_score: float = -1.0,
    ) -> Dict[str, float]:
        """Extract features from a secret detection result."""
        features = {}

        key_value = secret_match.get("value", "")
        key_type = secret_match.get("type", "")

        # Pattern specificity (known prefixes are more specific)
        specific_prefixes = [
            "sk_live_", "pk_live_", "rk_live_", "AKIA",
            "sq0atp-", "SG.", "xoxb-", "xoxp-", "ghp_",
            "gho_", "key-",
        ]
        features["has_prefix"] = 1.0 if any(key_value.startswith(p) for p in specific_prefixes) else 0.0
        features["pattern_specificity"] = 0.8 if features["has_prefix"] else 0.4

        # Key length (normalized)
        features["key_length"] = min(len(key_value) / 100.0, 1.0)

        # Shannon entropy
        features["entropy"] = FeatureExtractor._shannon_entropy(key_value)

        # Context
        if page_content:
            lower = page_content.lower()
            features["in_config_file"] = 1.0 if any(
                k in lower for k in ["config", ".env", "settings", "secret"]
            ) else 0.0
            features["in_html_comment"] = 1.0 if "<!--" in page_content else 0.0
            features["in_javascript"] = 1.0 if "<script" in lower else 0.0

            # Context score: is the key near relevant identifiers?
            key_idx = page_content.find(key_value)
            if key_idx >= 0:
                context = page_content[max(0, key_idx-200):key_idx+200].lower()
                context_keywords = [
                    "api", "key", "secret", "token", "password", "auth",
                    "credential", "config", "env", "private",
                ]
                features["context_score"] = min(
                    sum(1 for k in context_keywords if k in context) / 5.0, 1.0
                )
            else:
                features["context_score"] = 0.3
        else:
            features["in_config_file"] = 0.5
            features["in_html_comment"] = 0.0
            features["in_javascript"] = 0.5
            features["context_score"] = 0.5

        features["duplicate_count"] = 0.0  # Set externally
        features["live_validation_score"] = max(live_score, 0.0) if live_score >= 0 else 0.5

        return features

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string, normalized to 0-1."""
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )
        # Normalize: max entropy for printable ASCII is ~6.5 bits
        return min(entropy / 6.5, 1.0)


# ═══════════════════════════════════════════════════════════════
#   DECISION TREE (lightweight, no sklearn needed)
# ═══════════════════════════════════════════════════════════════

@dataclass
class TreeNode:
    """A node in the decision tree."""
    feature: str = ""
    threshold: float = 0.0
    left: Optional["TreeNode"] = None   # ≤ threshold
    right: Optional["TreeNode"] = None  # > threshold
    prediction: float = 0.5            # Leaf prediction
    is_leaf: bool = True
    samples: int = 0


class DecisionTree:
    """Minimal CART decision tree implementation."""

    def __init__(self, max_depth: int = 6, min_samples_split: int = 5):
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.root: Optional[TreeNode] = None

    def fit(self, samples: List[TrainingSample]):
        """Train the tree."""
        self.root = self._build(samples, depth=0)

    def predict(self, features: Dict[str, float]) -> float:
        """Predict probability of being a true positive."""
        if not self.root:
            return 0.5
        return self._traverse(self.root, features)

    def _build(self, samples: List[TrainingSample], depth: int) -> TreeNode:
        """Recursively build tree."""
        if not samples:
            return TreeNode(prediction=0.5, is_leaf=True)

        labels = [s.label for s in samples]
        mean_label = sum(labels) / len(labels) if labels else 0.5

        # Stop conditions
        if (depth >= self.max_depth or
            len(samples) < self.min_samples_split or
            len(set(labels)) <= 1):
            return TreeNode(
                prediction=mean_label,
                is_leaf=True,
                samples=len(samples),
            )

        # Find best split
        best_feature, best_threshold, best_gain = "", 0.0, -1.0
        best_left, best_right = [], []

        features = list(samples[0].features.keys())
        for feature in features:
            values = sorted(set(s.features.get(feature, 0.0) for s in samples))
            for i in range(len(values) - 1):
                threshold = (values[i] + values[i + 1]) / 2
                left = [s for s in samples if s.features.get(feature, 0.0) <= threshold]
                right = [s for s in samples if s.features.get(feature, 0.0) > threshold]

                if not left or not right:
                    continue

                gain = self._info_gain(samples, left, right)
                if gain > best_gain:
                    best_gain = gain
                    best_feature = feature
                    best_threshold = threshold
                    best_left = left
                    best_right = right

        if best_gain <= 0:
            return TreeNode(
                prediction=mean_label,
                is_leaf=True,
                samples=len(samples),
            )

        node = TreeNode(
            feature=best_feature,
            threshold=best_threshold,
            is_leaf=False,
            samples=len(samples),
        )
        node.left = self._build(best_left, depth + 1)
        node.right = self._build(best_right, depth + 1)
        return node

    def _info_gain(
        self,
        parent: List[TrainingSample],
        left: List[TrainingSample],
        right: List[TrainingSample],
    ) -> float:
        """Gini-based information gain."""
        def gini(samples):
            if not samples:
                return 0.0
            labels = [s.label for s in samples]
            n = len(labels)
            p1 = sum(labels) / n
            p0 = 1 - p1
            return 1 - (p1 ** 2 + p0 ** 2)

        n = len(parent)
        return gini(parent) - (
            len(left) / n * gini(left) +
            len(right) / n * gini(right)
        )

    def _traverse(self, node: TreeNode, features: Dict[str, float]) -> float:
        if node.is_leaf:
            return node.prediction
        val = features.get(node.feature, 0.0)
        if val <= node.threshold:
            return self._traverse(node.left, features) if node.left else node.prediction
        else:
            return self._traverse(node.right, features) if node.right else node.prediction


# ═══════════════════════════════════════════════════════════════
#   GRADIENT BOOSTED ENSEMBLE
# ═══════════════════════════════════════════════════════════════

class GradientBoostedClassifier:
    """
    Lightweight gradient boosted tree ensemble.
    No external dependencies — pure Python.
    """

    def __init__(
        self,
        n_trees: int = 10,
        max_depth: int = 4,
        learning_rate: float = 0.1,
        min_samples_split: int = 5,
    ):
        self.n_trees = n_trees
        self.max_depth = max_depth
        self.learning_rate = learning_rate
        self.min_samples_split = min_samples_split
        self.trees: List[DecisionTree] = []
        self.base_prediction = 0.0
        self._trained = False

    def fit(self, samples: List[TrainingSample]):
        """Train the ensemble."""
        if not samples:
            return

        # Base prediction (log-odds of positive class)
        pos = sum(1 for s in samples if s.label == 1)
        neg = len(samples) - pos
        if pos == 0 or neg == 0:
            self.base_prediction = 0.0
            return

        self.base_prediction = math.log(pos / max(neg, 1))
        predictions = [self.base_prediction] * len(samples)

        self.trees = []
        for t in range(self.n_trees):
            # Compute residuals (negative gradient of log loss)
            residuals = []
            for i, s in enumerate(samples):
                p = self._sigmoid(predictions[i])
                residual = s.label - p
                residuals.append(residual)

            # Create pseudo-training samples with residuals as labels
            pseudo = []
            for i, s in enumerate(samples):
                pseudo.append(TrainingSample(
                    features=s.features,
                    label=1 if residuals[i] > 0 else 0,
                    weight=abs(residuals[i]),
                ))

            # Fit a tree to residuals
            tree = DecisionTree(
                max_depth=self.max_depth,
                min_samples_split=self.min_samples_split,
            )
            tree.fit(pseudo)
            self.trees.append(tree)

            # Update predictions
            for i, s in enumerate(samples):
                leaf_val = tree.predict(s.features) - 0.5  # Center around 0
                predictions[i] += self.learning_rate * leaf_val

        self._trained = True
        logger.info(f"Trained {len(self.trees)} trees on {len(samples)} samples")

    def predict(self, features: Dict[str, float]) -> float:
        """Predict probability of true positive."""
        if not self._trained:
            return 0.5

        score = self.base_prediction
        for tree in self.trees:
            leaf_val = tree.predict(features) - 0.5
            score += self.learning_rate * leaf_val

        return self._sigmoid(score)

    @staticmethod
    def _sigmoid(x: float) -> float:
        """Sigmoid function with overflow protection."""
        if x > 30:
            return 1.0
        if x < -30:
            return 0.0
        return 1.0 / (1.0 + math.exp(-x))

    def to_dict(self) -> Dict:
        """Serialize the model."""
        return {
            "n_trees": self.n_trees,
            "max_depth": self.max_depth,
            "learning_rate": self.learning_rate,
            "base_prediction": self.base_prediction,
            "trained": self._trained,
        }


# ═══════════════════════════════════════════════════════════════
#   RULE-BASED FALLBACK
# ═══════════════════════════════════════════════════════════════

class RuleBasedFilter:
    """
    Deterministic rule-based scoring when ML model has insufficient data.
    Weighted feature scoring with configurable thresholds.
    """

    # Feature weights for SQLi scoring
    SQLI_WEIGHTS = {
        "injection_type_score": 2.0,
        "dbms_confidence": 1.5,
        "column_count_detected": 1.5,
        "injectable_columns": 1.0,
        "has_db_version": 2.0,
        "has_current_db": 1.5,
        "has_current_user": 1.5,
        "data_extracted": 3.0,
        "dios_success": 2.5,
        "error_pattern_count": 1.0,
        "response_diff_ratio": 0.5,
        "waf_detected": -0.5,  # WAF → higher FP risk
        "domain_history_score": 1.0,
    }

    # Feature weights for secret scoring
    SECRET_WEIGHTS = {
        "has_prefix": 2.0,
        "entropy": 1.5,
        "pattern_specificity": 1.0,
        "context_score": 1.5,
        "in_config_file": 1.0,
        "in_javascript": 0.5,
        "live_validation_score": 3.0,
        "key_length": 0.5,
    }

    def score_sqli(self, features: Dict[str, float]) -> Tuple[float, str]:
        """Rule-based SQLi scoring. Returns (score, reason)."""
        total_weight = 0.0
        weighted_sum = 0.0
        reasons = []

        for feat, weight in self.SQLI_WEIGHTS.items():
            val = features.get(feat, 0.0)
            weighted_sum += val * weight
            total_weight += abs(weight)

            # Track strong signals
            if val >= 0.8 and weight >= 1.5:
                reasons.append(f"{feat}={val:.1f}")
            elif val <= 0.2 and weight >= 1.5:
                reasons.append(f"weak_{feat}")

        score = weighted_sum / total_weight if total_weight else 0.5
        score = max(0.0, min(1.0, score))

        reason = "; ".join(reasons[:5]) if reasons else "rule-based scoring"
        return score, reason

    def score_secret(self, features: Dict[str, float]) -> Tuple[float, str]:
        """Rule-based secret scoring."""
        total_weight = 0.0
        weighted_sum = 0.0
        reasons = []

        for feat, weight in self.SECRET_WEIGHTS.items():
            val = features.get(feat, 0.0)
            weighted_sum += val * weight
            total_weight += abs(weight)

            if val >= 0.8 and weight >= 1.5:
                reasons.append(f"{feat}={val:.1f}")

        score = weighted_sum / total_weight if total_weight else 0.5
        score = max(0.0, min(1.0, score))

        reason = "; ".join(reasons[:5]) if reasons else "rule-based scoring"
        return score, reason


# ═══════════════════════════════════════════════════════════════
#   MAIN FILTER
# ═══════════════════════════════════════════════════════════════

class MLFilter:
    """
    ML-based false positive filter with rule-based fallback.

    Config fields:
        ml_filter_enabled: bool (True)
        ml_filter_threshold: float (0.5) — below this = filtered out
        ml_filter_model_path: str ("") — path to saved model
        ml_filter_min_training_samples: int (50)
        ml_filter_auto_train: bool (True)
    """

    def __init__(self, config: Any = None, db: Any = None):
        self.config = config
        self.db = db

        # Config
        self.enabled = True
        self.threshold = 0.5
        self.model_path = ""
        self.min_training_samples = 50
        self.auto_train = True

        if config:
            self.enabled = getattr(config, "ml_filter_enabled", True)
            self.threshold = getattr(config, "ml_filter_threshold", 0.5)
            self.model_path = getattr(config, "ml_filter_model_path", "")
            self.min_training_samples = getattr(config, "ml_filter_min_training_samples", 50)
            self.auto_train = getattr(config, "ml_filter_auto_train", True)

        # Components
        self.extractor = FeatureExtractor()
        self.rule_filter = RuleBasedFilter()
        self.sqli_model = GradientBoostedClassifier(n_trees=10, max_depth=4)
        self.secret_model = GradientBoostedClassifier(n_trees=8, max_depth=3)

        # Training data accumulator
        self._sqli_samples: List[TrainingSample] = []
        self._secret_samples: List[TrainingSample] = []

        # Domain history tracking
        self._domain_stats: Dict[str, Dict[str, int]] = {}  # domain -> {tp: x, fp: y}

        # Stats
        self.stats = {
            "sqli_checked": 0,
            "sqli_passed": 0,
            "sqli_filtered": 0,
            "secret_checked": 0,
            "secret_passed": 0,
            "secret_filtered": 0,
            "model_trained": False,
            "training_samples": 0,
        }

    # ─────────────────────────────────────────────
    #   PUBLIC API
    # ─────────────────────────────────────────────

    def filter_sqli(
        self,
        sqli_result: Any,
        original_response: str = "",
        injected_response: str = "",
        response_time_normal: float = 0.0,
        response_time_injected: float = 0.0,
        waf_detected: bool = False,
    ) -> FilterResult:
        """
        Filter an SQLi detection result.

        Returns FilterResult with is_positive=True if likely real.
        """
        url = getattr(sqli_result, "url", "")
        domain = self._get_domain(url)
        domain_history = self._get_domain_score(domain)

        features = self.extractor.extract_sqli_features(
            sqli_result=sqli_result,
            original_response=original_response,
            injected_response=injected_response,
            response_time_normal=response_time_normal,
            response_time_injected=response_time_injected,
            waf_detected=waf_detected,
            domain_history=domain_history,
        )

        # Use ML model if trained, else rule-based
        if self.sqli_model._trained:
            score = self.sqli_model.predict(features)
            reason = "ml_model"
        else:
            score, reason = self.rule_filter.score_sqli(features)

        is_positive = score >= self.threshold
        self.stats["sqli_checked"] += 1
        if is_positive:
            self.stats["sqli_passed"] += 1
        else:
            self.stats["sqli_filtered"] += 1

        return FilterResult(
            url=url,
            finding_type="sqli",
            is_positive=is_positive,
            confidence=abs(score - 0.5) * 2,  # Distance from threshold
            score=score,
            features=features,
            reason=reason,
        )

    def filter_secret(
        self,
        secret_match: Dict[str, Any],
        page_content: str = "",
        live_score: float = -1.0,
    ) -> FilterResult:
        """Filter a secret detection result."""
        features = self.extractor.extract_secret_features(
            secret_match=secret_match,
            page_content=page_content,
            live_score=live_score,
        )

        if self.secret_model._trained:
            score = self.secret_model.predict(features)
            reason = "ml_model"
        else:
            score, reason = self.rule_filter.score_secret(features)

        is_positive = score >= self.threshold
        self.stats["secret_checked"] += 1
        if is_positive:
            self.stats["secret_passed"] += 1
        else:
            self.stats["secret_filtered"] += 1

        return FilterResult(
            url=secret_match.get("url", ""),
            finding_type="secret",
            is_positive=is_positive,
            confidence=abs(score - 0.5) * 2,
            score=score,
            features=features,
            reason=reason,
        )

    # ─────────────────────────────────────────────
    #   FEEDBACK / TRAINING
    # ─────────────────────────────────────────────

    def add_feedback(
        self, finding_type: str, features: Dict[str, float],
        is_true_positive: bool,
    ):
        """
        Add human/automated feedback for model training.

        Called when a finding is confirmed as TP or FP.
        """
        sample = TrainingSample(
            features=features,
            label=1 if is_true_positive else 0,
        )

        if finding_type == "sqli":
            self._sqli_samples.append(sample)
        elif finding_type == "secret":
            self._secret_samples.append(sample)

        # Auto-train when enough data
        if self.auto_train:
            if finding_type == "sqli" and len(self._sqli_samples) >= self.min_training_samples:
                self._train_sqli()
            elif finding_type == "secret" and len(self._secret_samples) >= self.min_training_samples:
                self._train_secret()

    def add_sqli_feedback_auto(
        self, sqli_result: Any, confirmed: bool,
        features: Optional[Dict[str, float]] = None,
    ):
        """
        Automated feedback from downstream validation.

        e.g., if data extraction succeeds → confirmed=True
        e.g., if DIOS/dump fails completely → likely FP → confirmed=False
        """
        if features is None:
            features = self.extractor.extract_sqli_features(sqli_result)

        self.add_feedback("sqli", features, confirmed)

        # Update domain history
        domain = self._get_domain(getattr(sqli_result, "url", ""))
        if domain not in self._domain_stats:
            self._domain_stats[domain] = {"tp": 0, "fp": 0}
        if confirmed:
            self._domain_stats[domain]["tp"] += 1
        else:
            self._domain_stats[domain]["fp"] += 1

    def train(self):
        """Force training of all models."""
        self._train_sqli()
        self._train_secret()

    def _train_sqli(self):
        """Train the SQLi model."""
        if len(self._sqli_samples) < 10:
            return
        logger.info(f"Training SQLi model on {len(self._sqli_samples)} samples")
        self.sqli_model.fit(self._sqli_samples)
        self.stats["model_trained"] = True
        self.stats["training_samples"] = len(self._sqli_samples)

    def _train_secret(self):
        """Train the secret model."""
        if len(self._secret_samples) < 10:
            return
        logger.info(f"Training secret model on {len(self._secret_samples)} samples")
        self.secret_model.fit(self._secret_samples)

    # ─────────────────────────────────────────────
    #   BOOTSTRAP (seed with synthetic data)
    # ─────────────────────────────────────────────

    def bootstrap_training(self):
        """
        Seed models with synthetic training data based on heuristics.
        This provides reasonable starting accuracy before real feedback.
        """
        # Generate synthetic SQLi samples
        for _ in range(30):
            # True positive samples (realistic good findings)
            tp_features = {
                "response_diff_ratio": random.uniform(0.3, 0.9),
                "error_pattern_count": random.uniform(0.2, 1.0),
                "dbms_confidence": random.choice([0.0, 1.0, 1.0, 1.0]),
                "injection_type_score": random.choice([0.5, 0.7, 0.8, 1.0]),
                "column_count_detected": random.choice([0.0, 1.0, 1.0]),
                "injectable_columns": random.uniform(0.0, 0.6),
                "waf_detected": random.choice([0.0, 0.0, 0.0, 1.0]),
                "response_time_ratio": random.uniform(0.3, 1.0),
                "content_length_diff": random.uniform(0.1, 0.8),
                "reflection_count": random.uniform(0.0, 0.5),
                "param_count": random.uniform(0.1, 0.5),
                "https_score": random.choice([0.5, 1.0]),
                "has_db_version": random.choice([0.0, 1.0, 1.0]),
                "has_current_db": random.choice([0.0, 1.0, 1.0]),
                "has_current_user": random.choice([0.0, 1.0]),
                "data_extracted": random.choice([0.0, 1.0, 1.0]),
                "dios_success": random.choice([0.0, 0.0, 1.0]),
                "domain_history_score": random.uniform(0.3, 0.9),
            }
            self._sqli_samples.append(TrainingSample(features=tp_features, label=1))

        for _ in range(30):
            # False positive samples (noise, WAF blocks, generic errors)
            fp_features = {
                "response_diff_ratio": random.uniform(0.0, 0.3),
                "error_pattern_count": random.uniform(0.0, 0.4),
                "dbms_confidence": random.choice([0.0, 0.0, 0.0, 1.0]),
                "injection_type_score": random.uniform(0.0, 0.5),
                "column_count_detected": random.choice([0.0, 0.0, 1.0]),
                "injectable_columns": 0.0,
                "waf_detected": random.choice([0.0, 1.0, 1.0]),
                "response_time_ratio": random.uniform(0.0, 0.3),
                "content_length_diff": random.uniform(0.0, 0.2),
                "reflection_count": random.uniform(0.0, 0.3),
                "param_count": random.uniform(0.0, 0.3),
                "https_score": random.choice([0.5, 1.0]),
                "has_db_version": 0.0,
                "has_current_db": 0.0,
                "has_current_user": 0.0,
                "data_extracted": 0.0,
                "dios_success": 0.0,
                "domain_history_score": random.uniform(0.1, 0.5),
            }
            self._sqli_samples.append(TrainingSample(features=fp_features, label=0))

        self._train_sqli()

        # Generate synthetic secret samples
        for _ in range(25):
            tp = {
                "pattern_specificity": random.uniform(0.6, 1.0),
                "context_score": random.uniform(0.4, 1.0),
                "key_length": random.uniform(0.2, 0.6),
                "entropy": random.uniform(0.5, 1.0),
                "has_prefix": random.choice([0.0, 1.0, 1.0]),
                "in_config_file": random.choice([0.0, 1.0]),
                "in_html_comment": random.choice([0.0, 0.0, 1.0]),
                "in_javascript": random.choice([0.0, 1.0]),
                "duplicate_count": 0.0,
                "live_validation_score": random.uniform(0.5, 1.0),
            }
            self._secret_samples.append(TrainingSample(features=tp, label=1))

        for _ in range(25):
            fp = {
                "pattern_specificity": random.uniform(0.0, 0.5),
                "context_score": random.uniform(0.0, 0.4),
                "key_length": random.uniform(0.0, 0.3),
                "entropy": random.uniform(0.1, 0.5),
                "has_prefix": random.choice([0.0, 0.0, 1.0]),
                "in_config_file": 0.0,
                "in_html_comment": 0.0,
                "in_javascript": random.choice([0.0, 1.0]),
                "duplicate_count": random.uniform(0.0, 0.5),
                "live_validation_score": random.choice([0.0, 0.0, 0.5]),
            }
            self._secret_samples.append(TrainingSample(features=fp, label=0))

        self._train_secret()
        logger.info("Bootstrap training complete (60 SQLi + 50 secret samples)")

    # ─────────────────────────────────────────────
    #   HELPERS
    # ─────────────────────────────────────────────

    def _get_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            from urllib.parse import urlparse
            return urlparse(url).netloc
        except Exception:
            return ""

    def _get_domain_score(self, domain: str) -> float:
        """Get historical true positive rate for a domain."""
        stats = self._domain_stats.get(domain)
        if not stats:
            return 0.5
        total = stats["tp"] + stats["fp"]
        if total == 0:
            return 0.5
        return stats["tp"] / total

    def get_stats_text(self) -> str:
        """Human-readable stats for Telegram."""
        s = self.stats
        return (
            "🧠 <b>ML False Positive Filter</b>\n"
            f"Model trained: <b>{'Yes' if s['model_trained'] else 'No (rule-based)'}</b>\n"
            f"Training samples: <b>{s['training_samples']}</b>\n"
            f"SQLi: {s['sqli_passed']} passed / {s['sqli_filtered']} filtered "
            f"({s['sqli_checked']} total)\n"
            f"Secrets: {s['secret_passed']} passed / {s['secret_filtered']} filtered "
            f"({s['secret_checked']} total)"
        )
