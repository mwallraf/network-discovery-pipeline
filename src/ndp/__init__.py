"""network-discovery-pipeline: scan, parse and publish an SNMP device inventory."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("network-discovery-pipeline")
except PackageNotFoundError:  # running from a source tree without install
    __version__ = "0.0.0"
