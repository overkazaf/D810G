"""Control flow deflattening module."""


def register_handlers(server) -> None:
    from d810g_engine.deflattener.ollvm import deflat_ollvm
    server.register("deflat.run", deflat_ollvm)
