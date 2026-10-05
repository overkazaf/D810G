"""Dead Code Elimination module."""


def register_handlers(server) -> None:
    from d810g_engine.dce.eliminator import eliminate_dead_code
    server.register("dce.run", eliminate_dead_code)
