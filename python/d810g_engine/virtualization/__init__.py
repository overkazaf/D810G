"""Tigress VM devirtualization module."""


def register_handlers(server) -> None:
    from d810g_engine.virtualization.analyzer import analyze_vm
    from d810g_engine.virtualization.tracer import trace_vm
    server.register("vm.analyze", analyze_vm)
    server.register("vm.trace", trace_vm)
