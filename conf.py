project = 'KaraHoff'
copyright = '2025, SCS, European XFEL GmbH'
author = 'Martin Teichmann'

version = '0.7.0'
release = '0.7.0'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.intersphinx',
]

html_theme = 'alabaster'
autodoc_inherit_docstrings = False
autodoc_mock_imports = [
    'ebpfcat', 'karabo.common.scenemodel', 'karabo.common.project', 'karabo.common.api',
    'karabo.native.project', 'tabulate', 'dateutil', 'lxml', 'psutil', 'aiormq']


intersphinx_mapping = {
    "python": ("http://docs.python.org/3/", None),
    "karabo": ("https://karabo.pages.xfel.eu/framework/", None),
    "ebpfcat": ("https://ebpfcat.readthedocs.io/en/latest/", None),
}
