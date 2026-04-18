from setuptools import setup, find_packages

setup(
    name="aegis",
    version="0.1.0",
    description="Adaptive Endpoint Guardian Intelligence System",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "yara-python>=4.5.0",
        "watchdog>=4.0.0",
        "psutil>=5.9.0",
        "rich>=13.0.0",
        "pyyaml>=6.0",
        "scikit-learn>=1.3.0",
        "numpy>=1.24.0",
    ],
    entry_points={
        "console_scripts": [
            "aegis=aegis.__main__:main",
        ],
    },
)
