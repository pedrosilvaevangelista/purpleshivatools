from setuptools import setup, find_packages

setup(
    name="purplest",
    version="0.2",
    packages=find_packages(),
    install_requires=[],
    entry_points={
        "console_scripts": [
            "purplest=purplest.main:main",
            "purplest-arpscan=modules.blue_arpscan.modes:cli_entry",
        ]
    }
)