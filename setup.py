"""
SecureAI Platform — Package Setup
===================================
This file makes SecureAI installable as a Python package.

After running: pip install -e .
You can use: secureai scan docker
From anywhere in your terminal.

The -e flag means "editable install" — changes to your
code are reflected immediately without reinstalling.

entry_points defines the CLI command name:
    secureai = secureai.cli:cli
    means: when user types "secureai", run the cli()
    function from secureai/cli.py
"""

from setuptools import setup, find_packages

setup(
    # Package name — what appears on PyPI if published
    name="secureai-platform",

    # Version follows semantic versioning: MAJOR.MINOR.PATCH
    # 0.1.0 = initial development, not yet stable
    version="0.1.0",

    # Your information
    author="Jemel Padilla",
    author_email="your-email@example.com",

    # Short description — appears in pip search results
    description="AI-powered cloud security auditing platform",

    # Long description — pulled from README.md
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",

    # find_packages() automatically finds all Python packages
    # (directories with __init__.py files)
    packages=find_packages(),

    # Minimum Python version required
    python_requires=">=3.12",

    # Dependencies — same as requirements.txt
    install_requires=[
        "click>=8.1.7",
        "anthropic>=0.25.0",
        "rich>=13.7.0",
        "pyyaml>=6.0.1",
        "httpx>=0.27.0",
        "boto3>=1.34.0",
        "jinja2>=3.1.3",
    ],

    # CLI entry point
    # This creates the "secureai" command in your terminal
    entry_points={
        "console_scripts": [
            "secureai=secureai.cli:cli",
        ],
    },
)