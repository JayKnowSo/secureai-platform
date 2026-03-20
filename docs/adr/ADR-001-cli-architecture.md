# ADR-001: CLI Architecture — Click Framework

**Date:** 2026-03-20
**Status:** Accepted
**Author:** Jemel Padilla

## Context

SecureAI Platform requires a command-line interface that supports:
- Multiple commands (scan, analyze, report)
- Nested subcommands (scan docker, scan secrets)
- Option flags (--path, --severity, --output)
- Help text generation
- Version management

Python has two built-in options (argparse, optparse) and
several third-party frameworks (click, typer, docopt).

## Decision

Use Click as the CLI framework.

## Rationale

Click is the industry standard Python CLI framework.
Used by: Flask, Black, pip, AWS CLI, and hundreds of
major Python tools. Any Python engineer recognizes it.

Key advantages over argparse:
- Decorator-based — cleaner, more readable code
- Automatic help text generation
- Built-in command groups (scan → docker, secrets)
- Type validation on arguments
- Better error messages

Key advantages over Typer:
- More mature and battle-tested
- No type annotation requirement
- Broader community support

## Consequences

**Positive:**
- Clean, readable CLI code
- Automatic --help on every command
- Easy to add new commands and subcommands
- Industry-recognized pattern

**Negative:**
- External dependency (small — 50KB)
- Learning curve for Click decorators

## Security Relevance

CLI tools that handle security findings must have
clear, unambiguous interfaces. Click's explicit
option definitions prevent argument confusion attacks
where a user might pass unexpected input to the tool.

## Career Relevance

Click appears in job descriptions for Python tooling
and DevSecOps roles. Using it signals awareness of
Python ecosystem standards.
