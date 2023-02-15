from setuptools import setup, find_packages

NAME = "oktalogcollector"
version = {}
with open("src/oktalogcollector/version.py") as fp:
  exec(fp.read(), version)

setup(
    name="oktalogcollector",
    version=version["__version__"],
    packages=find_packages('src/oktalogcollector'),
    package_dir={'': 'src'},
    author="LogicMonitor",
    author_email="support@logicmonitor.com",
)
