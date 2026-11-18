# mcp-pc-control

Servidor **Model Context Protocol (MCP)** por `stdio` para monitoreo de hardware, gestión de procesos, automatización de escritorio en Windows y exploración segura de archivos dentro de directorios permitidos.

Diseñado para funcionar de forma nativa con **Mitsuru-bot**, **Claude Desktop**, **Cursor** o cualquier cliente compatible con MCP.

---

## Características principales

- **Métricas del sistema en tiempo real** (`systeminformation`): carga de CPU, uso de RAM, GPUs (VRAM y temperatura), discos y *uptime*.
- **Control seguro de procesos**: listado ordenado por CPU o RAM y terminación por PID con protección frente a procesos críticos del sistema Windows (`csrss.exe`, `lsass.exe`, `svchost.exe`, `explorer.exe`, etc.), PID del kernel (`<= 4`) y el propio servidor MCP.
- **Captura de pantalla en memoria**: captura la pantalla principal de Windows mediante PowerShell/.NET y devuelve una imagen PNG en Base64 sin escribir archivos temporales en disco.
- **Portapapeles sin inyección de shell**: lectura y escritura mediante `stdin` UTF-8 sin interpolación de comandos.
- **Audio y multimedia**: control preciso de volumen maestro (0–100 %), silencio/desilencio y teclas multimedia.
- **Energía y sesión de Windows**: bloqueo, suspensión, apagado, reinicio y cancelación de apagado, con soporte `dryRun`.
- **Listado de archivos con `PathGuard`**: restringido a `PC_ALLOWED_DIRS`, con bloqueo de *path traversal*, *symlinks* que escapen de la raíz, flujos alternativos NTFS (`ADS`) y archivos sensibles.

---

## Herramientas disponibles (9)

| Herramienta | Descripción | Parámetros principales |
| :--- | :--- | :--- |
| `get_system_metrics` | Devuelve carga de CPU (%), uso de RAM (GB), VRAM/temperaturas de GPU, espacio en disco y tiempo de actividad. | *(Sin parámetros)* |
| `list_processes` | Lista los principales procesos en ejecución ordenados por CPU o RAM. | `sortBy` (`"cpu"` \| `"mem"`, default `"cpu"`), `filterName` *(opcional)*, `limit` (1–30, default `15`) |
| `kill_process` | Termina un proceso no crítico por su PID tras validar que no sea un proceso protegido de Windows. | `pid` *(entero positivo requerido)* |
| `take_screenshot` | Captura la pantalla principal de Windows en memoria y devuelve la imagen como PNG en Base64. | *(Sin parámetros)* |
| `clipboard_get` | Lee el contenido de texto actual del portapapeles de Windows. | *(Sin parámetros)* |
| `clipboard_set` | Escribe texto de forma segura en el portapapeles de Windows mediante `stdin` (hasta 1 MB). | `text` *(string requerido)* |
| `media_volume` | Consulta o ajusta el volumen maestro de audio, estado de silencio o envía teclas multimedia. | `action` (`get` \| `set` \| `mute` \| `unmute` \| `toggle_mute` \| `volume_up` \| `volume_down` \| `play_pause`), `level` (0–100), `muted` *(boolean)*, `steps` (1–50, default `1`) |
| `system_power` | Ejecuta acciones de energía o sesión en Windows (`lock`, `sleep`, `shutdown`, `restart`, `cancel_shutdown`). | `action` *(requerido)*, `delaySeconds` (0–3600, default `10`), `dryRun` *(boolean, default `false`)* |
| `list_allowed_files` | Lista archivos y subdirectorios dentro de las rutas autorizadas por `PC_ALLOWED_DIRS`. | `directory` *(opcional; sin valor lista las raíces permitidas)*, `includeHidden` *(default `false`)*, `limit` (1–500, default `100`) |

---

## Instalación y compilación

Requisitos: **Windows 10 / 11** y **Node.js 20+**.

```bash
npm install
npm run build
```

Para verificar tipos y ejecutar las pruebas:

```bash
npm run typecheck
npm test
```

---

## Configuración de seguridad (`PC_ALLOWED_DIRS`)

La herramienta `list_allowed_files` utiliza `PathGuard` para garantizar que nunca se acceda fuera de los directorios explícitamente autorizados:

- **Valor por defecto:** si `PC_ALLOWED_DIRS` no está definida, solo se permiten:
  - `%USERPROFILE%\Documents`
  - `%USERPROFILE%\Downloads`
- **Múltiples directorios:** en Windows separa las rutas usando `;` (por ejemplo: `C:\Users\SENTINEL\Documents;D:\Proyectos`). También admite `,` como separador alternativo en `win32`.
- **Protecciones activas:**
  - Bloquea archivos y patrones sensibles aunque residan dentro de una carpeta permitida: `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa*`, `.git/config`, `loginusers.vdf` y `ssfn*`.
  - Resuelve rutas canónicas y bloquea enlaces simbólicos (*symlinks*) rotos o que apunten fuera de `PC_ALLOWED_DIRS`.
  - Rechaza sintaxis de flujos alternativos NTFS (`:`) y bytes nulos (`\0`).

---

## Integración en `mcp_servers.json`

Ejemplo compatible con **Mitsuru-bot** (`config/mcp_servers.json`), **Claude Desktop** y **Cursor**:

```json
{
  "mcpServers": {
    "pc_control": {
      "command": "node",
      "args": [
        "C:\\Users\\SENTINEL\\Documents\\mcp-pc-control\\dist\\index.js"
      ],
      "env": {
        "PC_ALLOWED_DIRS": "C:\\Users\\SENTINEL\\Documents;C:\\Users\\SENTINEL\\Downloads"
      },
      "disabled": false
    }
  }
}
```

> **Nota para sesiones remotas / Wake-on-LAN:** las herramientas interactivas de escritorio (`take_screenshot`, `clipboard_get`, `clipboard_set`, `media_volume` y `system_power` con `lock`/`sleep`) deben ejecutarse dentro de una sesión gráfica de usuario iniciada en Windows (por ejemplo, iniciando el cliente host con `--trigger logon`).
