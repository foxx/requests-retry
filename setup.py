#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="requests-retry",
    version="0.8.0",
    package_dir={'': 'pkg'},
    py_modules=['requests_retry'],
	#scripts=['pkg/requests_retry.py'],
    setup_requires=[
        'pytest-runner>=2.6',
        'yanc>=0.3'
    ],
    tests_require=[
        "pytest>=3.3",
        "pytest-cov>=2.5",
        "freezegun>=0.3",
        "python-coveralls>=2.9"
    ],
    install_requires=['requests'],
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4'
    ]
)
