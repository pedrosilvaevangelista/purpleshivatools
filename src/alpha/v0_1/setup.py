from setuptools import setup, find_packages

setup(
    name="purplest",  
    version="0.1",  
    packages=["v0_1", "modules"],  
    install_requires=[],  
    entry_points={  
        "console_scripts": [
            "purplest=main:main", 
            "purplest-morsetool=modules.util_morse:main"  
        ]
    }
)
