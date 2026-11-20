from siren_threatwatch.connectors.base import SOURCE_CATALOG, BaseConnector, ConnectorError, FetchResult
from siren_threatwatch.connectors.cisa_kev import CisaKevConnector
from siren_threatwatch.connectors.demo import SyntheticDemoConnector
from siren_threatwatch.connectors.mitre_attack import MitreAttackConnector
from siren_threatwatch.connectors.nvd import NvdConnector

# Implemented, runnable connectors, in recommended ingestion order (KEV first so NVD can enrich it).
# Phase 3 registers abuse.ch, OTX and RSS here.
CONNECTORS: dict[str, type[BaseConnector]] = {
    CisaKevConnector.name: CisaKevConnector,
    NvdConnector.name: NvdConnector,
    MitreAttackConnector.name: MitreAttackConnector,
    SyntheticDemoConnector.name: SyntheticDemoConnector,
}

__all__ = [
    "CONNECTORS",
    "SOURCE_CATALOG",
    "BaseConnector",
    "CisaKevConnector",
    "ConnectorError",
    "FetchResult",
    "MitreAttackConnector",
    "NvdConnector",
    "SyntheticDemoConnector",
]
