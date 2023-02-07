from setuptools import setup, find_packages

setup(
    name="oktalogcollector",
    packages=find_packages('src/oktalogcollector'),
    package_dir={'': 'src'}
)
