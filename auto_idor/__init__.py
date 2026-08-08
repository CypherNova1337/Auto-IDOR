"""IDOR-Auto: differential access-control testing for IDOR / BOLA bugs.

The tool does not guess vulnerabilities from status codes. It compares what
several distinct identities can *actually* read or act on, using the resource
owner and an unauthenticated baseline as reference oracles, so a finding means
"identity A obtained identity B's object" rather than "the endpoint returned
200".
"""

__version__ = "2.0.0"
__all__ = ["__version__"]
