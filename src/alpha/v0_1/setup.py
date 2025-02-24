from setuptools import setup, find_packages

setup(
    name="purplest",  
    version="0.1",  
    packages=find_packages(),
    install_requires=[],  
    entry_points={  
        "console_scripts": [
            "purplest=v0_1.main:main", 
            "purplest-morsetool=modules.util_morse:main"  
        ]
    }
)
