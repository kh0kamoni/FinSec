"""
Registry of all Bangladesh Bank Cybersecurity Framework Rule Checkers.
"""

from typing import List, Type
from mfs_checker.rules.base import BaseRule
from mfs_checker.rules.storage import DataAtRestRule
from mfs_checker.rules.logging import SensitiveLoggingRule
from mfs_checker.rules.transport import TransportSecurityRule
from mfs_checker.rules.cryptography import CryptographyStrengthRule
from mfs_checker.rules.keystore import KeystoreSecurityRule
from mfs_checker.rules.signing import TransactionSigningRule
from mfs_checker.rules.randomness import CryptographicRandomnessRule
from mfs_checker.rules.permissions import LeastPrivilegePermissionsRule
from mfs_checker.rules.manifest import ManifestHardeningRule
from mfs_checker.rules.obfuscation import SourceCodeProtectionRule
from mfs_checker.rules.secrets import HardcodedSecretsRule
from mfs_checker.rules.root_detection import RootDetectionRule
from mfs_checker.rules.screen_protection import ScreenProtectionRule
from mfs_checker.rules.biometrics import BiometricsRule

ALL_RULE_CLASSES: List[Type[BaseRule]] = [
    DataAtRestRule,            # BB-MFS-01 (4.1.5.2)
    SensitiveLoggingRule,      # BB-MFS-02 (4.1.3.21.b)
    TransportSecurityRule,     # BB-MFS-03 (4.1.5.19)
    CryptographyStrengthRule,  # BB-MFS-04 (4.1.5.19.c)
    KeystoreSecurityRule,      # BB-MFS-05 (4.1.5.18)
    TransactionSigningRule,    # BB-MFS-06 (4.1.3.10)
    CryptographicRandomnessRule, # BB-MFS-07 (4.1.5.18)
    LeastPrivilegePermissionsRule, # BB-MFS-08 (4.1.2.5)
    ManifestHardeningRule,     # BB-MFS-09 (4.1.8.10)
    SourceCodeProtectionRule,  # BB-MFS-10 (4.1.4.4)
    HardcodedSecretsRule,      # BB-MFS-11 (App C)
    RootDetectionRule,         # BB-MFS-12 (4.1.4.4, 5.1.2.19)
    ScreenProtectionRule,      # BB-MFS-13 (4.1.8.6)
    BiometricsRule             # BB-MFS-14 (4.1.3.21, 4.1.5.17)
]

def get_all_rules() -> List[BaseRule]:
    """Instantiate and return fresh instances of all 14 rules."""
    return [cls() for cls in ALL_RULE_CLASSES]
