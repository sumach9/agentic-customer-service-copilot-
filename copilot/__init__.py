"""Agentic Customer Service Copilot.

A small, honest demo: no LLM API key, no real customer data.
Structured customer facts live in SQLite (standing in for Snowflake),
unstructured policy truth lives in markdown files (retrieved with
TF-IDF, filtered by version and status), and the agent answers only
from those sources, with citations, or escalates to a human.
Protected by an enterprise-grade Einstein Trust Layer for prompt injection defense,
data masking, and zero-retention audit trails.
"""

from .agent import Agent, Answer
from .einstein_trust_layer import EinsteinTrustLayer, SecurityVerdict

