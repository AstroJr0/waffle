from setuptools import setup

setup(
    name="waffle",
    version="1.4.0",
    description="WAFFLE — Web Access Filter & Firewall for Local Environments",
    author="jayed",
    python_requires=">=3.9",
    py_modules=["waffle"],
    install_requires=[
        "cryptography>=41.0",
    ],
    entry_points={
        "console_scripts": [
            "waffle=waffle:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Environment :: Console",
        "Topic :: Internet :: Proxy Servers",
        "Topic :: Security",
    ],
)