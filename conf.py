extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.intersphinx',
]

templates_path = ['_templates']
numfig = True
source_suffix = '.rst'
master_doc = 'index'

project = 'EBPFCat'
copyright = '2020, Martin Teichmann'
author = 'Martin Teichmann'

release = "0.7"
version = "0.7.0"
language = "en"
exclude_patterns = ['_build']
pygments_style = 'sphinx'
todo_include_todos = False
html_theme = 'alabaster'
html_static_path = ['_static']
htmlhelp_basename = 'EBPFCat'

intersphinx_mapping = {'python': ('https://docs.python.org/3', None)}
