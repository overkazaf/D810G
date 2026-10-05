"""Bogus Control Flow detection and removal module."""


def register_handlers(server) -> None:
    from d810g_engine.bcf.detector import detect_and_remove_bcf
    server.register("bcf.run", detect_and_remove_bcf)
