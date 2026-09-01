"""
BB-MFS-03: Transport Layer Security & Certificate Pinning
Clauses: 4.1.5.19, 4.1.3.12
"""

from typing import List, Any
import re
from mfs_checker.rules.base import BaseRule
from mfs_checker.models import RuleResult, RuleStatus, Finding, Confidence

class TransportSecurityRule(BaseRule):
    def __init__(self):
        super().__init__("BB-MFS-03")

    def evaluate(self, apk: Any, dex_list: List[Any], analysis: Any) -> RuleResult:
        findings: List[Finding] = []
        strings = self.extract_all_strings(analysis, dex_list)

        # 1. Certificate Pinning Verification
        has_pinning = False
        pinning_indicators = [
            "okhttp3/CertificatePinner",
            "okhttp3.CertificatePinner",
            "pin-set",
            "TrustKit",
            "checkServerTrusted",
            "X509TrustManager"
        ]

        for ind in pinning_indicators:
            if any(ind in s for s in strings):
                has_pinning = True
                break

        # Check for permissive / empty trust manager
        has_insecure_trustmanager = False
        insecure_tm_indicators = [
            "TrustAllCertificates",
            "AllowAllHostnameVerifier",
            "NullTrustManager"
        ]
        for ind in insecure_tm_indicators:
            if any(ind.lower() in s.lower() for s in strings):
                has_insecure_trustmanager = True
                break

        # 2. Cleartext HTTP endpoint scan (excluding harmless schemas)
        ignored_domains = [
            "schemas.android.com",
            "www.w3.org",
            "apache.org",
            "xml.org",
            "localhost",
            "127.0.0.1"
        ]
        http_regex = re.compile(r'^http://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/.*)?$')
        cleartext_urls = []

        for s in strings:
            if s.startswith("http://"):
                if not any(ign in s for ign in ignored_domains):
                    if http_regex.match(s):
                        cleartext_urls.append(s)
                        if len(cleartext_urls) >= 10:
                            break

        # 3. Check Manifest / Network Security Config
        manifest_xml = self.get_manifest_xml_string(apk)
        allows_cleartext = False
        if 'android:usesCleartextTraffic="true"' in manifest_xml:
            allows_cleartext = True

        # Assess results
        if has_insecure_trustmanager or allows_cleartext or (cleartext_urls and not has_pinning):
            if allows_cleartext:
                findings.append(Finding(
                    description="AndroidManifest explicitly allows cleartext HTTP traffic (android:usesCleartextTraffic='true').",
                    confidence=Confidence.HIGH
                ))
            if has_insecure_trustmanager:
                findings.append(Finding(
                    description="Detected permissive or bypass TrustManager / HostnameVerifier.",
                    confidence=Confidence.HIGH
                ))
            for url in cleartext_urls[:5]:
                findings.append(Finding(
                    description=f"Insecure cleartext HTTP endpoint: {url}",
                    confidence=Confidence.HIGH,
                    code_snippet=url
                ))

            return RuleResult(
                rule_id=self.rule_id,
                clause=self.clause,
                title=self.title,
                function=self.function,
                category=self.category,
                status=RuleStatus.FAILED,
                severity=self.severity,
                penalty=self.penalty,
                remediation=self.remediation,
                findings=findings,
                details="Violation of Clause 4.1.5.19 & 4.1.3.12: Cleartext transmission or missing/bypassed TLS certificate validation."
            )
        elif not has_pinning:
            findings.append(Finding(
                description="HTTPS enforced, but no explicit Certificate Pinning (CertificatePinner or pin-set) was verified.",
                confidence=Confidence.MEDIUM
            ))
            return RuleResult(
                rule_id=self.rule_id,
                clause=self.clause,
                title=self.title,
                function=self.function,
                category=self.category,
                status=RuleStatus.WARNING,
                severity=self.severity,
                penalty=5,
                remediation=self.remediation,
                findings=findings,
                details="Complies with HTTPS baseline, but lacks recommended certificate pinning for public network resilience."
            )
        else:
            findings.append(Finding(
                description="Verified TLS enforcement and Certificate Pinning implementation.",
                confidence=Confidence.HIGH
            ))
            return RuleResult(
                rule_id=self.rule_id,
                clause=self.clause,
                title=self.title,
                function=self.function,
                category=self.category,
                status=RuleStatus.PASSED,
                severity=self.severity,
                penalty=0,
                remediation=self.remediation,
                findings=findings,
                details="Transport layer security compliant with Clause 4.1.5.19."
            )
