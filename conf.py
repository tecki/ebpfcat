project = 'KaraHoff'
copyright = '2025, SCS, European XFEL GmbH'
author = 'Martin Teichmann'

version = '0.7.0'
release = '0.7.0'

extensions = [
    'sphinx.ext.autodoc',
]

html_theme = 'alabaster'
autodoc_inherit_docstrings = False
autodoc_mock_imports = [
    'ebpfcat', 'karabo.common.scenemodel', 'karabo.common.project', 'karabo.common.api',
    'karabo.native.project', 'tabulate', 'dateutil', 'lxml', 'psutil', 'aiormq']
