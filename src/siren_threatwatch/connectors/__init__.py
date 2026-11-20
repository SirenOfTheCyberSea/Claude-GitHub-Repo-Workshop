from siren_threatwatch.connectors.base import SOURCE_CATALOG, BaseConnector, ConnectorError, FetchResult
from siren_threatwatch.connectors.cisa_kev import CisaKevConnector
from siren_threatwatch.connectors.demo import SyntheticDemoConnector

# Implemented, runnable connectors. Later phases register NVD, MITRE ATT&CK, abuse.ch, OTX and RSS here.
CONNECTORS: dict[str, type[BaseConnector]] = {
    CisaKevConnector.name: CisaKevConnector,
    SyntheticDemoConnector.name: SyntheticDemoConnector,
}

__all__ = [
    "CONNECTORS",
    "SOURCE_CATALOG",
    "BaseConnector",
    "CisaKevConnector",
    "ConnectorError",
    "FetchResult",
    "SyntheticDemoConnector",
]
