# PENTEST-CORE v4.0

Agente de Pentesting Autonomo con IA. Aprende de errores y successes automaticamente.

## Caracteristicas

- **Pentesting Autonomo**: IA decide y ejecuta ataques
- **Memoria Adaptativa**: Aprende de errores successes
- **Deteccion CVE**: Extrae CVE automaticamente
- **Auto-Explotacion**: Explota CVEs cuando los detecta
- **Reverse Shells**: Generador automatico
- **Nuclei + SearchSploit**: Integracion completa
- **Reportes**: HTML/MD/JSON/CSV

## Uso

```bash
python3 main.py 10.10.10.123
```

## Sistema de Memoria Adaptativa

El agente ahora **APRENDE**:

### Lo que hace:
1. **Registra comandos que fallan**: Si un comando falla, lo memoriza
2. **Registra comandos que funcionan**: Si algo funciona, lo recuerda
3. **Carga contexto al iniciar**: Las lecciones se injectan en el prompt
4. **Post-mortem al finalizar**: Muestra patrones exitosos/fallidos

### Como funciona:

```
Sesion 1:
  - nmap -sV target → OK (funciono)
  - gobuster dir -u target → FAIL (no encontro nada)
  
Sesion 2:
  → Contexto cargado:
    "SI FUNCIONO: nmap -sV FLAGS"
    "NO FUNCIONO: gobuster dir FLAGS"
  → IA evita repetir gobuster o prueba otra estrategia
```

### Base de datos:

Las lecciones se guardan en `vibe_hacker.db` tabla `lessons`:
- `command_pattern`: Patron del comando (sin IPs/ports)
- `success`: 1 = funciono, 0 = fallo
- `count`: Cuantas veces se uso
- `last_used`: Ultima vez usado

## Comandos Interactivos

```
!cve <CVE-ID>      - Info de CVE
!cves              - Listar CVEs detectados
!exploit <term>    - Buscar exploits
!shell <IP> [PORT] - Generar reverse shells
!shells            - Listar tipos de shells
!nuclei <url>      - Scan con Nuclei
```

## Ejemplo de Output

```
============================================================
   PENTEST-CORE v4.0 - AGENTE DE PENTESTING AUTONOMO
============================================================

[+] Sesion: 1 | Target: 10.10.10.123
[i] Modo: AGRESIVO

[🧠] Contexto adaptativo cargado:
NO FUNCIONO ANTES:
  - gobuster dir FLAGS (fallo 2 veces)
  - nikto FLAGS (fallo 1 vez)

SI FUNCIONO ANTES:
  - nmap -sV FLAGS (funciono 5 veces)
  - searchsploit FLAGS (funciono 3 veces)

[THINKING]
Veo puerto 80 abierto con Apache. Voy a probar nikto? No, el contexto dice que nikto no funciono antes. Voy directo a searchsploit para la version.

[RECON] Apache 2.4.49 - buscar exploit
   → Porque ya se que nikto falla, voy directo a exploit
   Expected: CVE para Apache
```

## Post-Mortem

Al finalizar cada sesion:

```
==================================================
POST-MORTEM DE LA SESION
==================================================

SUCCESS (5 comandos):
  ✓ nmap -sV FLAGS -> Exit: 0
  ✓ searchsploit apache FLAGS -> Exit: 0
  ✓ curl FLAGS -> Exit: 0

FAILURES (2 comandos):
  ✗ nikto FLAGS
    Reason: Timeout
  ✗ sqlmap FLAGS
    Reason: Exit: 1

TOP PATRONES EXITOSOS:
  nmap -sV FLAGS: 5 veces
  searchsploit FLAGS: 3 veces

PATRONES FALLIDOS:
  nikto FLAGS: 2 veces
  sqlmap FLAGS: 1 vez
==================================================
```

## Config

Edita `~/.vibehackerrc`:

```json
{
    "ollama_url": "http://localhost:11434/api/chat",
    "model": "qwen2.5-coder:7b",
    "auto_exploit_cve": true,
    "aggressive_mode": true
}
```

## Requisitos

```bash
pip install requests
ollama pull qwen2.5-coder:7b
```

## Testing

```bash
pytest test_main.py -v
```
