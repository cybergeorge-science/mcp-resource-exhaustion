"""dos_module: availability/DoS attack-module scaffold for the MCP DoS paper.

See harness/REPORT.md for a full explanation of what in this package is
VERIFIED against the real MCPSecBench source (github.com/AIS2Lab/MCPSecBench)
versus ASSUMED because no equivalent exists upstream.

Short version: MCPSecBench has no plugin/module registry, no AttackModule
interface, and no per-run JSON results schema. It is a flat set of scripts
orchestrated by one main.py that drives GUI MCP hosts and records
manually-verified attack-success codes in a CSV. This package therefore
defines its own conventional plugin architecture (registry + ABC + YAML
config + JSON results) rather than "matching" something that isn't there.
"""
