"""CLI entry point for pearcer.

For now, this just wires into a placeholder main() that will later
initialize capture backends and the GUI.
"""

from .gui.app import run_gui


def main() -> None:
    """Launch the pearcer GUI application."""
    run_gui()


if __name__ == "__main__":  # pragma: no cover
    main()
