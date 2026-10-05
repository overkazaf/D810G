"""OLLVM string decryption module."""


def register_handlers(server) -> None:
    from d810g_engine.strings.decryptor import decrypt_strings
    server.register("strings.decrypt", decrypt_strings)
