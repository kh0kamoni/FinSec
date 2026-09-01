"""
Abstract Base Rule and Helper Primitives for Bangladesh Bank Cybersecurity Auditing.
"""

from abc import ABC, abstractmethod
import math
import re
from typing import List, Dict, Any, Optional, Set
from mfs_checker.models import RuleResult, RuleStatus, Severity, Finding, Confidence
from mfs_checker.config import BB_CLAUSE_DEFINITIONS, SEVERITY_WEIGHTS

class BaseRule(ABC):
    """Abstract Base Class for all Bangladesh Bank Compliance Rules."""

    def __init__(self, rule_id: str):
        if rule_id not in BB_CLAUSE_DEFINITIONS:
            raise ValueError(f"Unknown rule ID: {rule_id}")
        self.rule_id = rule_id
        meta = BB_CLAUSE_DEFINITIONS[rule_id]
        self.clause = meta["clause"]
        self.title = meta["title"]
        self.function = meta["function"]
        self.category = meta["category"]
        self.severity = Severity(meta["severity"])
        self.penalty = SEVERITY_WEIGHTS[meta["severity"]]
        self.remediation = meta["remediation"]

    @abstractmethod
    def evaluate(self, apk: Any, dex_list: List[Any], analysis: Any) -> RuleResult:
        """
        Evaluate the APK against the regulatory rule.
        :param apk: Androguard APK object or mock equivalent
        :param dex_list: List of DalvikVMFormat objects
        :param analysis: Androguard Analysis object
        :return: RuleResult with status and evidence findings
        """
        pass

    # Helper Utilities
    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string (in bits per character)."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return - sum(p * math.log2(p) for p in prob)

    @staticmethod
    def get_manifest_xml_string(apk: Any) -> str:
        """Safely extract XML representation of AndroidManifest."""
        if hasattr(apk, "get_android_manifest_xml"):
            try:
                xml_obj = apk.get_android_manifest_xml()
                if xml_obj is not None:
                    import xml.etree.ElementTree as ET
                    return ET.tostring(xml_obj, encoding="unicode")
            except Exception:
                pass
        if hasattr(apk, "xml"):
            # Mock or direct xml attribute
            return str(getattr(apk, "xml", ""))
        return ""

    @staticmethod
    def extract_all_strings(analysis: Any, dex_list: List[Any]) -> Set[str]:
        """Extract all literal strings present in DEX files."""
        strings: Set[str] = set()
        if analysis and hasattr(analysis, "get_strings"):
            try:
                for s in analysis.get_strings():
                    val = getattr(s, "get_value", lambda: str(s))()
                    if isinstance(val, str):
                        strings.add(val)
            except Exception:
                pass
        if dex_list:
            for dex in dex_list:
                if hasattr(dex, "get_strings"):
                    try:
                        for s in dex.get_strings():
                            if isinstance(s, str):
                                strings.add(s)
                    except Exception:
                        pass
        return strings
