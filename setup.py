"""
Simple, lightweight, and easily extensible STOMP message broker.
"""
import os.path
import warnings
import re

try:
    from setuptools import setup, find_packages
except ImportError:
    from distribute_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

from certify import __version__

news = os.path.join(os.path.dirname(__file__), 'docs', 'news.txt')
news = open(news).read()
parts = re.split(r'([0-9\.]+)\s*\n\r?-+\n\r?', news)
found_news = ''
for i in range(len(parts)-1):
    if parts[i] == __version__:
        found_news = parts[i+i]
        break
if not found_news:
    warnings.warn('No news for this version found.')
    
long_description = """

"""

if found_news:
    title = 'Changes in %s' % __version__
    long_description += "\n%s\n%s\n" % (title, '-'*len(title))
    long_description += found_news

setup(
    name='certify',
    version=__version__,
    description=__doc__,
    long_description=long_description,
    keywords='CA certmaster ssl openssl',
    license='GPL',
    author='Hans Lellelid',
    author_email='hans@xmpl.org',
    url='http://github.com/hozn/certify',
    packages=find_packages(exclude=['ez_setup', 'tests', 'tests.*']),
    package_data={'certify': ['config/*.cfg*', 'tests/resources/*']},
    zip_safe=False, # We use resource_filename for logging configuration and some unit tests.
    include_package_data=True,
    test_suite='nose.collector',
    tests_require=['nose', 'coverage', 'mock'],
    install_requires=[
          'setuptools',
          'pyopenssl'
    ],
    extras_require={
        #'daemon': ['python-daemon'],
        #'sqlalchemy': ['SQLAlchemy']
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)",
        "Programming Language :: Python :: 2.4",
        "Programming Language :: Python :: 2.5",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
    ],
    entry_points="""
    [console_scripts]
    certify-server = certify.scripts.server:main
    certify-ca = certify.scripts.ca:main
    certify-request = certify.scripts.request:main
    """,
)
