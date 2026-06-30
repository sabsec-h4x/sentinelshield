# ─────────────────────────────────────────────────────────────────
#  core/rule_engine.py — Signature-Based Attack Detection
#
#  HOW IT WORKS:
#  1. Loads all JSON rule files from the /rules directory at startup
#  2. Compiles each pattern into a regex (faster matching)
#  3. For each request, runs every rule against the parsed payload
#  4. Returns a list of all matches with scores and details
#
#  WHY JSON RULES?
#  Keeping rules in JSON files (not hardcoded in Python) means you
#  can add/edit/remove rules without touching any Python code.
#  In real WAFs, rules are updated daily as new attacks are discovered.
# ─────────────────────────────────────────────────────────────────

import re
import json
import os
import sys
from dataclasses import dataclass, field
from typing import List, Dict, Optional

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from config import RULES_DIR
from core.parser import ParsedRequest


# ── Data Structures ───────────────────────────────────────────────

@dataclass
class RuleMatch:
    """Represents a single rule that was triggered by a request."""
    rule_id:       str    # e.g., "SQLI-001"
    rule_name:     str    # e.g., "Classic OR-based SQLi"
    category:      str    # e.g., "SQL Injection"
    category_id:   str    # e.g., "sqli"
    severity:      str    # LOW / MEDIUM / HIGH / CRITICAL
    description:   str    # Human-readable explanation
    matched_value: str    # The actual string that triggered the rule
    base_score:    float  # Score contribution from this rule
    score_modifier:float  # Multiplier for this specific rule

    @property
    def final_score(self) -> float:
        return self.base_score * self.score_modifier


@dataclass
class DetectionResult:
    """The complete detection result for one request."""
    matches:       List[RuleMatch] = field(default_factory=list)
    total_score:   float = 0.0
    categories:    List[str] = field(default_factory=list)  # unique attack types found
    is_malicious:  bool = False

    def add_match(self, match: RuleMatch):
        self.matches.append(match)
        self.total_score += match.final_score
        if match.category not in self.categories:
            self.categories.append(match.category)
        self.is_malicious = True


# ── Rule Engine Class ─────────────────────────────────────────────

class RuleEngine:
    """
    Loads attack signatures from JSON files and matches them against
    incoming HTTP requests.

    USAGE:
        engine = RuleEngine()
        engine.load_rules()
        result = engine.analyze(parsed_request)
    """

    def __init__(self):
        self._rule_sets: List[Dict] = []          # Raw loaded rule sets
        self._compiled:  List[Dict] = []           # Pre-compiled regex patterns
        self._loaded = False

    def load_rules(self):
        """
        Reads all *_rules.json files from the rules directory and
        compiles each pattern into a regex object.
        
        We compile regexes ONCE at startup rather than on every request
        because compilation is slow — matching a compiled regex is fast.
        """
        rule_files = [
            f for f in os.listdir(RULES_DIR)
            if f.endswith("_rules.json")
        ]

        if not rule_files:
            print(f"⚠️  No rule files found in {RULES_DIR}")
            return

        for filename in sorted(rule_files):
            filepath = os.path.join(RULES_DIR, filename)
            try:
                with open(filepath, "r") as f:
                    rule_set = json.load(f)

                # Compile each rule's pattern into a regex
                compiled_rules = []
                for rule in rule_set.get("rules", []):
                    try:
                        compiled_pattern = re.compile(
                            rule["pattern"],
                            re.IGNORECASE | re.DOTALL
                            # IGNORECASE: matches regardless of uppercase/lowercase
                            # DOTALL: . matches newlines too (important for multi-line payloads)
                        )
                        compiled_rules.append({
                            "id":             rule["id"],
                            "name":           rule["name"],
                            "description":    rule.get("description", ""),
                            "score_modifier": rule.get("score_modifier", 1.0),
                            "compiled":       compiled_pattern,
                        })
                    except re.error as e:
                        print(f"⚠️  Invalid regex in {filename} rule {rule['id']}: {e}")

                self._compiled.append({
                    "category":    rule_set["category"],
                    "category_id": rule_set["category_id"],
                    "severity":    rule_set["severity"],
                    "base_score":  rule_set["score"],
                    "rules":       compiled_rules,
                })

                print(f"✅ Loaded {len(compiled_rules)} rules from {filename}")

            except (json.JSONDecodeError, KeyError) as e:
                print(f"❌ Error loading {filename}: {e}")

        total = sum(len(rs["rules"]) for rs in self._compiled)
        print(f"🛡️  Rule Engine ready: {total} signatures across {len(self._compiled)} categories")
        self._loaded = True

    def analyze(self, parsed: ParsedRequest) -> DetectionResult:
        """
        Run all rules against the parsed request.
        Returns a DetectionResult with all matches and the total threat score.
        """
        if not self._loaded:
            self.load_rules()

        result = DetectionResult()

        # Check the full combined payload against every rule
        targets = [parsed.full_payload] + parsed.all_values

        for rule_set in self._compiled:
            for rule in rule_set["rules"]:
                for target in targets:
                    if not target:
                        continue
                    match = rule["compiled"].search(target)
                    if match:
                        # Found a match! Record it.
                        matched_text = match.group(0)
                        # Truncate to 100 chars so we don't store giant payloads
                        if len(matched_text) > 100:
                            matched_text = matched_text[:100] + "..."

                        rule_match = RuleMatch(
                            rule_id        = rule["id"],
                            rule_name      = rule["name"],
                            category       = rule_set["category"],
                            category_id    = rule_set["category_id"],
                            severity       = rule_set["severity"],
                            description    = rule["description"],
                            matched_value  = matched_text,
                            base_score     = rule_set["base_score"],
                            score_modifier = rule["score_modifier"],
                        )
                        result.add_match(rule_match)

                        # Once a rule matches, don't check the same rule again
                        # (avoid duplicate matches for the same attack type)
                        break

        return result

    def get_loaded_rules_summary(self) -> List[Dict]:
        """Returns a summary of all loaded rules — useful for the /rules API endpoint."""
        summary = []
        for rs in self._compiled:
            summary.append({
                "category":    rs["category"],
                "category_id": rs["category_id"],
                "severity":    rs["severity"],
                "rule_count":  len(rs["rules"]),
                "rules": [
                    {"id": r["id"], "name": r["name"], "description": r["description"]}
                    for r in rs["rules"]
                ]
            })
        return summary


# ── Singleton Instance ────────────────────────────────────────────
# We create ONE engine instance and reuse it for all requests.
# This avoids reloading and recompiling rules on every request.
rule_engine = RuleEngine()
