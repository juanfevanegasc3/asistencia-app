# Sistema de Asistencia

Aplicación web para la gestión de cursos, estudiantes y asistencia académica, desplegada íntegramente en **Cloudflare Workers** con **Cloudflare D1** como base de datos.

El sistema está pensado para instituciones educativas y docentes que necesitan registrar asistencia de forma rápida, tanto manualmente desde el panel como mediante códigos QR que los estudiantes escanean desde su teléfono.

No requiere servidor propio, proceso de build ni dependencias de frontend: el Worker sirve la API y la interfaz web desde un único archivo.

---

## Tabla de contenidos

- [Funcionalidades](#funcionalidades)
- [Roles y permisos](#roles-y-permisos)
- [Arquitectura](#arquitectura)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Requisitos](#requisitos)
- [Despliegue](#despliegue)
- [Desarrollo local](#desarrollo-local)
- [Guía de uso](#guía-de-uso)
- [Referencia de la API](#referencia-de-la-api)
- [Modelo de datos](#modelo-de-datos)
- [Seguridad](#seguridad)
- [Respaldos y migraciones](#respaldos-y-migraciones)
- [Buenas prácticas y mejoras recomendadas](#buenas-prácticas-y-mejoras-recomendadas)

---

## Funcionalidades

### Gestión académica

- Creación y eliminación de cursos con nombre y descripción.
- Registro de estudiantes con documento, email y teléfono.
- Inscripción de estudiantes en uno o varios cursos.
- Consulta de estudiantes inscritos por curso.
- Contadores de cursos, estudiantes y docentes en el panel.
- Vista de asistencia por curso y fecha con cuatro estados: **presente**, **ausente**, **tarde** y **justificado**.
- Guardado masivo de asistencia en una sola operación.
- Acción rápida para marcar a todo el curso como presente.
- Historial de asistencia por curso, ordenado por fecha.
- Interfaz adaptable a computador, tablet y teléfono.

### Registro por código QR

- **QR de asistencia:** generado por el docente para un curso y una fecha. Es válido durante **3 horas**.
- **QR de inscripción:** permite que un estudiante cree su cuenta y quede inscrito automáticamente en un curso. Es válido durante **7 días**.
- **QR de registro general:** abre el formulario de registro sin inscribir en un curso.
- El estudiante escanea el código con su teléfono, inicia sesión y su asistencia queda registrada.
- El enlace del QR se puede copiar para compartirlo por otros medios.

### Cuentas y acceso

- **Administrador:** acceso mediante clave maestra.
- **Docentes:** registro con código de invitación opcional, inicio de sesión con email y contraseña.
- **Estudiantes:** registro con documento y contraseña; pueden reclamar un registro previamente creado por un docente.
- Restablecimiento de contraseñas mediante claves temporales generadas por el sistema.
- Cambio de contraseña desde el perfil del estudiante.
- Sesiones firmadas con HMAC: 7 días para docentes y 30 días para estudiantes.

### Panel del estudiante

- Consulta de sus cursos inscritos.
- Porcentaje de asistencia por curso.
- Resumen de estados: presente, tarde, justificado y ausente.
- Cambio de contraseña.
- Confirmación inmediata al marcar asistencia o inscribirse mediante QR.

---

## Roles y permisos

| Rol | Acceso | Alcance |
| --- | --- | --- |
| Administrador | Clave maestra (`API_KEY`) | Acceso total, incluida la gestión de docentes |
| Docente | Email y contraseña | Cursos, estudiantes, inscripciones, asistencia e historial |
| Estudiante | Documento y contraseña | Consulta de sus cursos, su asistencia y cambio de contraseña |

> **Nota:** actualmente todos los docentes comparten el mismo alcance sobre los cursos y estudiantes. No existe separación de datos por docente. Ver [mejoras recomendadas](#buenas-prácticas-y-mejoras-recomendadas).

---

## Arquitectura

```text
┌────────────────────┐         ┌──────────────────────────────┐         ┌──────────────┐
│ Navegador / móvil  │  HTTP   │ Cloudflare Worker            │   D1    │ Base de datos│
│ HTML + CSS + JS    │ ──────> │ src/index.js                 │ ──────> │ asistencia_db│
│ Panel y portal     │ <────── │ API REST + interfaz embebida │ <────── │ SQLite       │
└────────────────────┘         └──────────────────────────────┘         └──────────────┘
```

- Un único Worker atiende:
  - las rutas de la API bajo `/api/*`;
  - la interfaz web en el resto de rutas.
- No hay framework ni etapa de compilación. El HTML, CSS y JavaScript se sirven desde `src/index.js`.
- Las contraseñas se derivan con **PBKDF2-SHA256** y salt aleatorio.
- Las sesiones se firman con **HMAC-SHA256** y no se almacenan en la base de datos.
- Los tokens de los QR también están firmados y tienen expiración.

---

## Estructura del proyecto

```text
asistencia-app/
├── src/
│   └── index.js                        # Worker: API, autenticación y frontend
├── schema.sql                          # Esquema inicial de D1
├── migration_002_login_estudiantes.sql # Migración para bases de datos antiguas
├── wrangler.toml                       # Configuración del Worker y de D1
├── .dev.vars.example                   # Variables de entorno para desarrollo local
├── .gitignore
└── README.md
```

---

## Requisitos

- Cuenta gratuita en [Cloudflare](https://dash.cloudflare.com).
- [Node.js](https://nodejs.org) 18 o superior.
- Wrangler, la CLI oficial de Cloudflare.

```bash
npm install -g wrangler
wrangler login
```

---

## Despliegue

### 1. Crear o reutilizar la base de datos D1

Para una instalación nueva:

```bash
wrangler d1 create asistencia_db
```

El comando devuelve un bloque similar a este:

```toml
[[d1_databases]]
binding = "DB"
database_name = "asistencia_db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

Copia el `database_id` en `wrangler.toml`, reemplazando el valor existente.

> Si la base de datos ya existe y contiene información, **no la vuelvas a crear**. Conserva el `database_id` actual.

### 2. Aplicar el esquema

Para una base de datos nueva:

```bash
wrangler d1 execute asistencia_db --remote --file=./schema.sql
```

Si la base de datos fue creada antes de la incorporación del login de estudiantes, aplica también la migración una sola vez:

```bash
wrangler d1 execute asistencia_db --remote --file=./migration_002_login_estudiantes.sql
```

> No ejecutes `migration_002_login_estudiantes.sql` en una base creada con el `schema.sql` actual: las columnas ya existen y el comando fallará sin afectar los datos.

### 3. Configurar los secretos

Los secretos no deben guardarse en `wrangler.toml` ni en el repositorio. Configúralos con Wrangler:

```bash
wrangler secret put API_KEY
wrangler secret put SESSION_SECRET
```

- `API_KEY`: clave maestra del administrador.
- `SESSION_SECRET`: cadena larga y aleatoria usada para firmar sesiones y códigos QR.

Opcionalmente, para exigir un código de invitación al registrar docentes:

```bash
wrangler secret put CODIGO_DOCENTE
```

> Si `CODIGO_DOCENTE` no está configurado, cualquier persona que conozca la URL del sistema puede registrarse como docente. Se recomienda configurarlo en producción.

### 4. Desplegar

```bash
wrangler deploy
```

Wrangler mostrará la URL pública del Worker, por ejemplo:

```text
https://asistencia-app.<tu-subdominio>.workers.dev
```

### 5. Verificar

1. Abre la URL del Worker.
2. Ingresa con la clave maestra desde **Acceso administrativo**.
3. Crea un curso.
4. Registra un estudiante e inscríbelo.
5. Genera un QR de asistencia y pruébalo desde un teléfono.

---

## Desarrollo local

Crea un archivo `.dev.vars` a partir de `.dev.vars.example`:

```bash
cp .dev.vars.example .dev.vars
```

Ajusta los valores y aplica el esquema sobre la base local:

```bash
wrangler d1 execute asistencia_db --local --file=./schema.sql
wrangler dev --local
```

La aplicación quedará disponible en `http://localhost:8787` o en el puerto indicado por Wrangler.

> `.dev.vars` está excluido del repositorio. Nunca publiques claves reales.

---

## Guía de uso

### Administrador

1. Entra desde **Acceso administrativo** con la clave maestra.
2. Crea cursos desde **Cursos**.
3. Registra docentes desde **Docentes**.
4. Gestiona estudiantes, inscripciones, asistencia e historial desde el panel.

### Docente

1. Regístrate desde la pestaña **Docente** con el código de invitación, si está configurado.
2. Crea o selecciona un curso.
3. Registra estudiantes e inscríbelos.
4. Para tomar asistencia:
   - entra en **Tomar asistencia**;
   - selecciona el curso y la fecha;
   - marca el estado de cada estudiante;
   - pulsa **Guardar asistencia**.
5. Para usar QR:
   - pulsa **Generar QR de asistencia**;
   - proyecta o comparte el código;
   - los estudiantes inscritos quedarán marcados como presentes;
   - pulsa **Actualizar lista** para ver los cambios.

### Estudiante

1. Escanea el QR de inscripción o abre el enlace proporcionado por el docente.
2. Crea su cuenta con nombre, documento y contraseña.
3. Inicia sesión.
4. En clase, escanea el QR de asistencia.
5. Consulta sus cursos y porcentaje de asistencia en **Mi panel**.

### Restablecer una contraseña

- Un docente puede restablecer la clave de un estudiante desde **Estudiantes**.
- El administrador puede restablecer la clave de un docente desde **Docentes**.
- El sistema muestra una clave temporal una única vez. La persona debe cambiarla después de ingresar.

---

## Referencia de la API

Todas las rutas usan el prefijo `/api`. Las respuestas son JSON.

### Rutas públicas

| Método | Ruta | Descripción |
| --- | --- | --- |
| `POST` | `/login` | Inicio de sesión del administrador con `apiKey` |
| `POST` | `/login-docente` | Inicio de sesión de docente |
| `POST` | `/register-docente` | Registro de docente |
| `POST` | `/login-estudiante` | Inicio de sesión de estudiante |
| `POST` | `/register-estudiante` | Registro o reclamación de cuenta de estudiante |
| `GET` | `/public/token-info?token=...` | Información pública de un QR |

### Rutas autenticadas

Las rutas protegidas aceptan:

- `X-API-Key: <API_KEY>` para el administrador.
- `Authorization: Bearer <token>` para docentes y estudiantes.

| Método | Ruta | Acceso | Descripción |
| --- | --- | --- | --- |
| `POST` | `/attendance/session` | Admin / docente | Genera token QR de asistencia |
| `POST` | `/enroll/session` | Admin / docente | Genera token QR de inscripción |
| `POST` | `/attendance/self` | Estudiante | Registra su propia asistencia |
| `POST` | `/enroll/self` | Estudiante | Se inscribe mediante QR |
| `GET` | `/me` | Estudiante | Cursos y resumen de asistencia |
| `POST` | `/me/password` | Estudiante | Cambia su contraseña |
| `GET` | `/teachers` | Admin | Lista docentes |
| `POST` | `/teachers` | Admin | Crea docente |
| `DELETE` | `/teachers/:id` | Admin | Elimina docente |
| `POST` | `/teachers/:id/reset-password` | Admin | Restablece clave de docente |
| `GET` | `/courses` | Admin / docente | Lista cursos |
| `POST` | `/courses` | Admin / docente | Crea curso |
| `DELETE` | `/courses/:id` | Admin / docente | Elimina curso |
| `GET` | `/courses/:id/students` | Admin / docente | Estudiantes inscritos |
| `GET` | `/courses/:id/history` | Admin / docente | Historial de asistencia |
| `GET` | `/students` | Admin / docente | Lista estudiantes |
| `POST` | `/students` | Admin / docente | Crea estudiante |
| `DELETE` | `/students/:id` | Admin / docente | Elimina estudiante |
| `POST` | `/students/:id/reset-password` | Admin / docente | Restablece clave de estudiante |
| `POST` | `/enrollments` | Admin / docente | Inscribe estudiante en curso |
| `DELETE` | `/enrollments/:id` | Admin / docente | Elimina inscripción |
| `GET` | `/attendance?course_id=...&fecha=...` | Admin / docente | Asistencia de un curso en una fecha |
| `POST` | `/attendance` | Admin / docente | Guarda asistencia por lote |

### Ejemplo de guardado de asistencia

```json
{
  "fecha": "2026-10-24",
  "registros": [
    { "enrollment_id": 1, "estado": "presente" },
    { "enrollment_id": 2, "estado": "tarde" },
    { "enrollment_id": 3, "estado": "ausente" }
  ]
}
```

---

## Modelo de datos

| Tabla | Descripción | Campos principales |
| --- | --- | --- |
| `courses` | Cursos | `id`, `nombre`, `descripcion`, `created_at` |
| `students` | Estudiantes | `id`, `nombre`, `documento`, `email`, `telefono`, `password_hash`, `salt` |
| `teachers` | Docentes | `id`, `nombre`, `email`, `password_hash`, `salt` |
| `enrollments` | Inscripciones | `id`, `student_id`, `course_id` |
| `attendance` | Asistencia | `id`, `enrollment_id`, `fecha`, `estado` |

Restricciones relevantes:

- `students.documento` es único.
- `teachers.email` es único.
- Un estudiante no puede inscribirse dos veces en el mismo curso.
- Solo puede existir un registro de asistencia por inscripción y fecha.
- `attendance.estado` acepta únicamente `presente`, `ausente`, `tarde` o `justificado`.
- Las inscripciones y asistencias se eliminan en cascada al borrar un curso o un estudiante.

---

## Seguridad

### Controles implementados

- Contraseñas derivadas con **PBKDF2-SHA256**, salt aleatorio y 100 000 iteraciones.
- Sesiones y tokens QR firmados con **HMAC-SHA256**.
- Expiración de sesiones y códigos QR.
- Separación de permisos por rol.
- Validación de estado de asistencia mediante restricción de base de datos.
- Restablecimiento de contraseñas con claves temporales de un solo uso.
- Variables sensibles gestionadas mediante secretos de Wrangler.

### Consideraciones

- La aplicación usa **una única clave de administrador**. No existe un sistema de usuarios administradores.
- La clave maestra se guarda en `localStorage` del navegador después del inicio de sesión. Un XSS podría exponerla; el frontend escapa los datos dinámicos, pero se recomienda mantener el código actualizado.
- No hay límite de intentos de inicio de sesión ni bloqueo de cuentas.
- Los tokens firmados no se pueden revocar de forma individual antes de su expiración.
- Los docentes tienen acceso global a cursos, estudiantes y asistencias.
- El QR se genera mediante un servicio externo (`api.qrserver.com`), que recibe el enlace codificado.

Para un entorno con datos sensibles se recomienda:

1. Publicar el Worker detrás de **Cloudflare Access**.
2. Configurar reglas de **rate limiting** en Cloudflare.
3. Usar contraseñas largas y rotar `API_KEY` y `SESSION_SECRET` periódicamente.
4. Mantener `CODIGO_DOCENTE` configurado para controlar el registro de docentes.
5. Realizar respaldos antes de cada cambio importante.

---

## Respaldos y migraciones

### Crear un respaldo

```bash
wrangler d1 export asistencia_db --remote --output=backup-asistencia.sql
```

Guarda el archivo en un lugar seguro y fuera del repositorio.

### Aplicar cambios al esquema

- `schema.sql` es idempotente para tablas e índices (`IF NOT EXISTS`) y se usa en instalaciones nuevas.
- Las migraciones existentes son aditivas y no eliminan datos.
- Antes de aplicar una migración en producción, crea un respaldo.
- Para cambios futuros se recomienda numerar las migraciones (`003_...`, `004_...`) o adoptar `wrangler d1 migrations`.

### Actualizar la aplicación

```bash
wrangler deploy
```

La base de datos y los datos existentes no se modifican al desplegar una nueva versión del Worker.

---

## Buenas prácticas y mejoras recomendadas

Estas mejoras no están implementadas en la versión actual y deben evaluarse según el alcance del proyecto:

- **Separar los datos por docente:** agregar `courses.teacher_id` y filtrar todas las consultas por el docente autenticado.
- **Auditoría de asistencia:** registrar quién marcó cada estado, cuándo y desde qué método (manual o QR).
- **Evitar sobrescrituras por QR:** no reemplazar un estado manual (`justificado`, `ausente`) cuando un estudiante escanea el código.
- **Validar fechas en la API:** aceptar únicamente el formato `YYYY-MM-DD`.
- **Eliminación lógica:** usar un campo `activo` en lugar de borrar cursos y estudiantes, para conservar el historial.
- **Edición de registros:** agregar endpoints para actualizar cursos y estudiantes sin eliminarlos.
- **Paginación y filtros:** aplicar límites al historial y a los listados para cursos grandes.
- **Revocación de sesiones:** incorporar una versión de contraseña o una tabla de sesiones para invalidar tokens.
- **Rate limiting:** proteger los inicios de sesión y el registro contra fuerza bruta.
- **QR propio:** generar los códigos dentro del Worker para no depender de un servicio externo.
- **Aprobación de inscripciones:** requerir confirmación del docente cuando un estudiante se inscribe por QR.
- **Cloudflare Access:** restringir el panel administrativo a correos o dominios autorizados.

---

## Licencia y uso

Proyecto de uso interno para gestión académica. Ajusta la licencia y las condiciones de uso según las necesidades de tu institución antes de distribuirlo públicamente.
