# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html
import sys
from pathlib import Path
from sphinx_pyproject import SphinxConfig

project_root = Path(__file__).parents[1].resolve()

sys.path.insert(0, (project_root / "socks_router").as_posix())

config = SphinxConfig(
    (project_root / "pyproject.toml").as_posix(),
    globalns=globals(),
    style="poetry",
)

autoapi_dirs = [(project_root / "socks_router").as_posix()]

html_static_path = ["static"]
templates_path = ["templates"]
exclude_patterns = ["build", "Thumbs.db", ".DS_Store"]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

def skip_generic_variables(app, what, name, obj, skip, options) -> bool:
    if len(obj.name) == 1:
        skip = True
    return skip

def setup(sphinx):
    sphinx.connect("autoapi-skip-member", skip_generic_variables)
