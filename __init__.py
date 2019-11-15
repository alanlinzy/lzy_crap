import playground
from .protocol import CRAPClientFactory, CRAPServerFactory

CRAPConnector = playground.Connector(protocolStack=(CRAPClientFactory(),CRAPServerFactory()))
playground.setConnector("crap", CRAPConnector)
playground.setConnector("team2stack", CRAPConnector)
