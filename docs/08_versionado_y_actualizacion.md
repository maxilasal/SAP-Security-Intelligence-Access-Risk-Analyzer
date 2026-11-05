# Versionado, instalación desde Git y actualización

El repositorio es la fuente oficial: <https://github.com/maxilasal/sap-security-intelligence-access-risk-analyzer>.
Cada instalación (servidor) es un clon; los datos de cada instalación **no** viajan al repositorio.

## Qué está en Git y qué no

| En el repositorio | Solo en cada instalación (ignorado por Git) |
|---|---|
| Código, plantillas, reglas YAML de ejemplo, scripts, documentación, pruebas y el sistema ficticio de pruebas | `data\` (base SQLite, snapshots, logs, cachés, clave de sesión, certificados y claves TLS), `config\settings.yaml`, `.venv\` |

Las contraseñas SAP no están en ningún archivo: quedan en el Administrador de credenciales de Windows.

## Cómo se trabaja

1. Cada cambio se hace en una rama (`feature/descripcion`, `fix/descripcion` o `chore/descripcion`).
2. Al subirla, GitHub Actions ejecuta todas las pruebas en Windows y Linux (workflow **Pruebas**).
3. Con las pruebas en verde, la rama se integra a `main` (la versión estable, la que se instala).
4. Cuando el cambio merece una versión nueva, en el mismo cambio se sube el número en `pyproject.toml` y
   `src/sapsec/__init__.py`, y se agrega su sección en `CHANGELOG.md`.
5. Al llegar a `main` con las pruebas en verde, el workflow **Publicar versión** crea solo el tag `vX.Y.Z` y la
   Release con las notas del CHANGELOG. Si la versión ya existe, no hace nada.
6. En cada servidor: `scripts\actualizar.ps1` (o `-Version vX.Y.Z` para una versión puntual).

Versiones con formato `MAYOR.MENOR.PARCHE`: MAYOR = cambio incompatible (por ejemplo, en la base o en las reglas),
MENOR = funciones nuevas, PARCHE = correcciones. La versión instalada figura en el menú lateral de la aplicación.

Las reglas (`config/rules/*.yaml`) tienen además su propio campo `version`; cada análisis guarda el hash de las
reglas usadas, así se sabe con qué criterio se generó cada hallazgo.

## Instalar en un servidor nuevo

Requisitos: Git para Windows (`winget install --id Git.Git -e`) y Python 3.11–3.13 de 64 bits.

```powershell
cd C:\sapsec
```

```powershell
git clone https://github.com/maxilasal/sap-security-intelligence-access-risk-analyzer.git sap-security-analyzer
```

```powershell
cd sap-security-analyzer
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

## Pasar una instalación existente (descargada como zip) a Git

Se conserva todo lo local (`data\`, `config\settings.yaml`, `.venv\`): Git solo administra los archivos de la aplicación.

```powershell
cd C:\sapsec\sap-security-analyzer
```

```powershell
Copy-Item -Recurse data ..\respaldo-data-antes-de-git
```

```powershell
git init -b main
```

```powershell
git remote add origin https://github.com/maxilasal/sap-security-intelligence-access-risk-analyzer.git
```

```powershell
git fetch origin
```

```powershell
git reset --hard origin/main
```

```powershell
git branch --set-upstream-to=origin/main main
```

`git reset --hard` reemplaza los archivos de la aplicación por los del repositorio y **no** toca los ignorados
(`data\`, `config\settings.yaml`, `.venv\`). `git status` debe quedar limpio.

## Actualizar

Cerrar la ventana de la aplicación (si está abierta con `run.ps1`) y ejecutar:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\actualizar.ps1
```

El script trae la última versión de `main`, muestra qué cambió, reinstala dependencias solo si cambiaron, aplica las
migraciones de la base (`init-db`) y, si la aplicación se inicia con Windows, la reinicia. Para instalar una versión
puntual: `scripts\actualizar.ps1 -Version v0.1.0`; para volver a la última: `scripts\actualizar.ps1`.
