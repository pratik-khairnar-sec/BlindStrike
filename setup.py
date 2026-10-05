#!/usr/bin/env python3
from setuptools import setup

setup(
    name="blindstrike",
    version="7.0.0",
    py_modules=["blindstrike"],
    install_requires=[
        "requests>=2.31.0",
        "urllib3>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "blindstrike=blindstrike:main",
        ],
    },
)
