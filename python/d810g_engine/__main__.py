"""Entry point: python -m d810g_engine [cli|server]"""

import sys


def main() -> int:
    """Dispatch to CLI or server mode based on argv."""
    if len(sys.argv) > 1 and sys.argv[1] == "cli":
        from d810g_engine.cli import main as cli_main
        sys.argv = [sys.argv[0]] + sys.argv[2:]  # strip "cli" from argv
        return cli_main()
    else:
        from d810g_engine.server import main as server_main
        return server_main()


if __name__ == "__main__":
    sys.exit(main())
