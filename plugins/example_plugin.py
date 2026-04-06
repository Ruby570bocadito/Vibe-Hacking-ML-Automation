"""
Plugin de ejemplo para Vibe-Hacker v3.0

Para cargar plugins, coloca archivos .py en la carpeta plugins/
El plugin debe definir una función `register(manager)` que se ejecutará al cargar.
"""


def register(manager):
    """
    Registra comandos personalizados en el manager.
    """

    def custom_scan(target: str) -> str:
        """Ejecuta un scan personalizado."""
        return f"Nmap rapido para {target}"

    manager.register_command("custom_scan", custom_scan)

    print("[+] Plugin 'example' cargado exitosamente")
