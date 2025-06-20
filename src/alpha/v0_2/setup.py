from setuptools import setup, find_packages

setup(
    name="purplest",
    version="0.2",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'purplest=purplest.main:main',
            'purplest-arpscan=modules.blue_arpscan.modes:main'
        ],
    },
    install_requires=[
        'rich',
        'keyboard',
    ],
    author="Purple Shiva Team",
    description="Red & Blue Team Security Tools",
    python_requires='>=3.6',
)