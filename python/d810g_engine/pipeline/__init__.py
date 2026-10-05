"""Multi-pass deobfuscation pipeline."""


def register_handlers(server) -> None:
    from d810g_engine.pipeline.orchestrator import run_pipeline
    server.register("pipeline.run", run_pipeline)
