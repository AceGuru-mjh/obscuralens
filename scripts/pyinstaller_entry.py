"""PyInstaller entry point for the standalone executable."""

import multiprocessing

from obscuralens.cli import main

if __name__ == '__main__':
    multiprocessing.freeze_support()
    main()
