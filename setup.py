#!/usr/bin/env python

import setuptools

setuptools.setup(
    name="idawasm",
    version="0.1",
    description="IDA loader and processor for WebAssembly.",
    author="Willi Ballenthin",
    author_email="william.ballenthin@fireeye.com",
    license="Apache 2.0 License",
    packages=setuptools.find_packages(),
    install_requires=[
        'wasm',
    ],
)
