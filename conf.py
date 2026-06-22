extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx.ext.intersphinx',
]

templates_path = ['_templates']
numfig = True
source_suffix = '.rst'
master_doc = 'index'

project = 'EBPFCat'
copyright = '2026, European XFEL GmbH'
author = 'Martin Teichmann'

release = "1.3"
version = "1.3.1"
language = "en"
exclude_patterns = ['_build']
pygments_style = 'sphinx'
todo_include_todos = False
html_theme = 'alabaster'
html_logo = 'ebpfcat.svg'
html_favicon = 'ebpfcat.svg'
html_static_path = ['_static']
htmlhelp_basename = 'EBPFCat'

intersphinx_mapping = {'python': ('https://docs.python.org/3', None)}
autodoc_mock_imports = ['softioc']
autodoc_inherit_docstrings = False
