# Sistema de Asistencia

Aplicación web para la gestión de cursos, docentes, estudiantes y asistencia académica, desplegada íntegramente en **Cloudflare Workers** con **Cloudflare D1** como base de datos.

El sistema está pensado para instituciones educativas y docentes que necesitan registrar asistencia de forma rápida, tanto manualmente desde el panel como mediante códigos QR que los estudiantes escanean desde su teléfono.

No requiere servidor propio, proceso de build ni dependencias de frontend: el Worker sirve la API y la interfaz web desde un único archivo. Los códigos QR se generan dentro del propio Worker.

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

- Creación, edición y **archivado lógico** de cursos con nombre y descripción.
- Asignación opcional de un docente responsable a cada curso.
- Registro, edición y archivado de estudiantes con documento, email y teléfono.
- Asignación opcional de un docente responsable a cada estudiante.
- Inscripción de estudiantes en uno o varios cursos.
- Consulta de estudiantes inscritos por curso.
- Contadores de cursos activos, estudiantes activos y docentes en el panel.
- Vista de asistencia por curso y fecha con cuatro estados: **presente**, **ausente**, **tarde** y **justificado**.
- Guardado masivo de asistencia en una sola operación (máximo 300 registros por lote).
- Acción rápida para marcar a todo el curso como presente.
- Historial de asistencia por curso con filtros de fecha, paginación y datos de auditoría.
- Interfaz adaptable a computador, tablet y teléfono.

### Registro por código QR

- **QR de asistencia:** generado por el docente para un curso y una fecha. Es válido durante **3 horas**.
- **QR de inscripción:** permite que un estudiante cree su cuenta y quede inscrito automáticamente en un curso. Es válido durante **7 días**.
- **QR de registro general:** abre el formulario de registro sin inscribir en un curso.
- Los QR se generan en el servidor y se entregan como SVG; no dependen de servicios externos.
- El estudiante escanea el código con su teléfono, inicia sesión y su asistencia queda registrada.
- Si el estudiante ya tenía un estado manual para esa fecha, el QR **no lo sobrescribe**.
- El enlace del QR se puede copiar para compartirlo por otros medios.

### Cuentas y acceso

- **Administrador:** inicio de sesión con clave maestra y sesión en cookie `HttpOnly`, `SameSite=Strict`, de 12 horas.
- **Docentes:** registro con código de invitación, inicio de sesión con email y contraseña.
- **Estudiantes:** registro con documento y contraseña; pueden reclamar un registro previamente creado por un docente.
- Restablecimiento de contraseñas mediante claves temporales generadas por el sistema.
- Cambio de contraseña desde el perfil del estudiante.
- Sesiones firmadas con HMAC: 7 días para docentes y 30 días para estudiantes.
- Revocación de sesiones al cambiar o restablecer una contraseña.
- Límite de intentos por IP para inicios de sesión y registros.

### Panel del estudiante

- Consulta de sus cursos inscritos.
- Porcentaje de asistencia por curso.
- Resumen de estados: presente, tarde, justificado y ausente.
- Cambio de contraseña.
- Confirmación inmediata al marcar asistencia o inscribirse mediante QR, indicando si el registro ya existía.

---

## Roles y permisos

| Rol | Acceso | Alcance |
| --- | --- | --- |
| Administrador | Clave maestra (`API_KEY`) y cookie de sesión | Acceso total, incluida la gestión de docentes y la asignación de responsables |
| Docente | Email y contraseña | Sus propios cursos y estudiantes, más los registros institucionales (`teacher_id = NULL`) |
| Estudiante | Documento y contraseña | Consulta de sus cursos, su asistencia y cambio de contraseña |

Reglas de alcance:

- Un curso o estudiante con `teacher_id = NULL` es **institucional**: lo ven todos los docentes, pero solo el administrador puede editarlo o archivarlo.
- Un docente solo puede editar, archivar o restablecer claves de registros que le pertenecen.
- El docente también ve estudiantes inscritos en sus cursos, aunque pertenezcan a otro responsable; sobre ellos no tiene permisos de gestión.
- Los estudiantes archivados no pueden iniciar sesión, registrarse de nuevo ni canjear códigos QR.
- Los cursos archivados no aceptan inscripciones, asistencia ni nuevos QR.

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
- La sesión del administrador viaja en una cookie `HttpOnly`; no se guarda la clave maestra en `localStorage`.
- La asistencia guarda metadatos de auditoría y un historial de cambios en `attendance_audit`.

---

## Estructura del proyecto

```text
asistencia-app/
├── src/
│   ├── index.js                          # Worker: API, autenticación y frontend
│   ├── qrcode.mjs                        # Generador de QR (vendorizado, MIT)
│   └── qrcode_UTF8.mjs                   # Soporte UTF-8 para el generador de QR
├── schema.sql                            # Esquema completo para instalaciones nuevas
├── migration_002_login_estudiantes.sql   # Migración histórica para bases muy antiguas
├── migration_003_seguridad_y_alcance.sql # Migración aditiva para bases existentes
├── wrangler.toml                         # Configuración del Worker y de D1
├── .dev.vars.example                     # Variables de entorno para desarrollo local
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

> Si la base de datos ya existe y contiene información, **no la vuelvas a crear**. Conserva el `database_id` actual y aplica la migración del paso 2.

### 2. Aplicar el esquema o la migración

**Instalación nueva** (base vacía):

```bash
wrangler d1 execute asistencia_db --remote --file=./schema.sql
```

**Base de datos existente** (con datos de versiones anteriores):

```bash
# 1) Haz un respaldo antes de cualquier cambio
wrangler d1 export asistencia_db --remote --output=backup-antes-003.sql

# 2) Aplica la migración aditiva una sola vez
wrangler d1 execute asistencia_db --remote --file=./migration_003_seguridad_y_alcance.sql
```

> `migration_003_seguridad_y_alcance.sql` es **aditiva**: agrega columnas, tablas e índices sin borrar ni modificar registros existentes. No la ejecutes sobre una base creada con el `schema.sql` actual, porque las columnas ya existirían.
>
> `migration_002_login_estudiantes.sql` solo es necesaria en bases muy antiguas que aún no tengan `password_hash` y `salt` en `students`. Si las columnas ya existen, el comando fallará sin afectar los datos.

### 3. Configurar los secretos

Los secretos no deben guardarse en `wrangler.toml` ni en el repositorio. Configúralos con Wrangler:

```bash
wrangler secret put API_KEY
wrangler secret put SESSION_SECRET
```

- `API_KEY`: clave maestra del administrador.
- `SESSION_SECRET`: cadena larga y aleatoria usada para firmar sesiones y códigos QR. Es obligatoria para iniciar sesión.

Opcionalmente, para habilitar el registro público de docentes:

```bash
wrangler secret put CODIGO_DOCENTE
```

> Si `CODIGO_DOCENTE` **no** está configurado, el registro público de docentes queda deshabilitado. El administrador aún puede crear cuentas de docente desde el panel.

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

Para conservar una base local separada o probar una migración sin afectar tus datos de desarrollo:

```bash
wrangler d1 execute asistencia_db --local --persist-to ./.wrangler/prueba --file=./schema.sql
wrangler dev --local --persist-to ./.wrangler/prueba
```

> `.dev.vars` está excluido del repositorio. Nunca publiques claves reales.

---

## Guía de uso

### Administrador

1. Entra desde **Acceso administrativo** con la clave maestra.
2. Crea cursos desde **Cursos** y, si lo deseas, asígnales un docente responsable.
3. Registra docentes desde **Docentes**.
4. Gestiona estudiantes, inscripciones, asistencia e historial desde el panel.
5. Usa **Editar** para modificar un registro y **Archivar** para ocultarlo sin perder su historial. Activa **Mostrar archivados** para verlos y restaurarlos.

### Docente

1. Regístrate desde la pestaña **Docente** con el código de invitación, si está habilitado.
2. Crea o selecciona un curso. Los cursos que crees quedan automáticamente a tu nombre.
3. Registra estudiantes e inscríbelos.
4. Para tomar asistencia:
   - entra en **Tomar asistencia**;
   - selecciona el curso y la fecha;
   - marca el estado de cada estudiante;
   - pulsa **Guardar asistencia**.
5. Para usar QR:
   - pulsa **Generar QR de asistencia**;
   - proyecta o comparte el código;
   - los estudiantes inscritos quedarán marcados como presentes si aún no tenían un estado;
   - pulsa **Actualizar lista** para ver los cambios.
6. En **Historial** puedes filtrar por rango de fechas, ver el origen del registro (manual o QR) y quién lo realizó.

### Estudiante

1. Escanea el QR de inscripción o abre el enlace proporcionado por el docente.
2. Crea su cuenta con nombre, documento y contraseña.
3. Inicia sesión.
4. En clase, escanea el QR de asistencia.
5. Consulta sus cursos y porcentaje de asistencia en **Mi panel**.

### Restablecer una contraseña

- Un docente puede restablecer la clave de un estudiante que le pertenezca desde **Estudiantes**.
- El administrador puede restablecer la clave de cualquier estudiante o docente.
- La sesión anterior de la persona queda invalidada automáticamente.
- El sistema muestra una clave temporal una única vez. La persona debe cambiarla después de ingresar.

---

## Referencia de la API

Todas las rutas usan el prefijo `/api`. Las respuestas son JSON.

### Rutas públicas

| Método | Ruta | Descripción |
| --- | --- | --- |
| `POST` | `/login` | Inicio de sesión del administrador con `apiKey`; establece la cookie de sesión |
| `POST` | `/logout` | Cierra la sesión del administrador y elimina la cookie |
| `POST` | `/login-docente` | Inicio de sesión de docente |
| `POST` | `/register-docente` | Registro de docente (requiere `CODIGO_DOCENTE` configurado) |
| `POST` | `/login-estudiante` | Inicio de sesión de estudiante |
| `POST` | `/register-estudiante` | Registro o reclamación de cuenta de estudiante |
| `GET` | `/public/token-info?token=...` | Información pública de un QR |

### Autenticación de rutas protegidas

- En el navegador, el administrador usa la cookie `asistencia_admin`.
- Los clientes de API pueden usar `X-API-Key: <API_KEY>` para el administrador.
- Docentes y estudiantes usan `Authorization: Bearer <token>`.

### Rutas autenticadas

| Método | Ruta | Acceso | Descripción |
| --- | --- | --- | --- |
| `GET` | `/session` | Todos | Rol, nombre e id de la sesión actual |
| `POST` | `/qr` | Admin / docente | Genera un SVG de código QR para los datos indicados |
| `POST` | `/attendance/session` | Admin / docente | Genera token QR de asistencia |
| `POST` | `/enroll/session` | Admin / docente | Genera token QR de inscripción |
| `POST` | `/attendance/self` | Estudiante | Registra su propia asistencia |
| `POST` | `/enroll/self` | Estudiante | Se inscribe mediante QR |
| `GET` | `/me` | Estudiante | Cursos y resumen de asistencia |
| `POST` | `/me/password` | Estudiante | Cambia su contraseña y devuelve un token nuevo |
| `GET` | `/teachers` | Admin | Lista docentes |
| `POST` | `/teachers` | Admin | Crea docente |
| `DELETE` | `/teachers/:id` | Admin | Elimina docente |
| `POST` | `/teachers/:id/reset-password` | Admin | Restablece clave de docente |
| `GET` | `/courses` | Admin / docente | Lista cursos visibles |
| `POST` | `/courses` | Admin / docente | Crea curso |
| `PATCH` | `/courses/:id` | Admin / docente propietario | Edita nombre, descripción, responsable o estado activo |
| `DELETE` | `/courses/:id` | Admin / docente propietario | Archiva el curso |
| `GET` | `/courses/:id/students` | Admin / docente | Estudiantes inscritos y activos |
| `GET` | `/courses/:id/history` | Admin / docente | Historial paginado con filtros |
| `GET` | `/students` | Admin / docente | Lista estudiantes visibles |
| `POST` | `/students` | Admin / docente | Crea estudiante |
| `PATCH` | `/students/:id` | Admin / docente propietario | Edita datos, responsable o estado activo |
| `DELETE` | `/students/:id` | Admin / docente propietario | Archiva el estudiante |
| `POST` | `/students/:id/reset-password` | Admin / docente propietario | Restablece clave de estudiante |
| `POST` | `/enrollments` | Admin / docente propietario del curso | Inscribe estudiante en curso |
| `DELETE` | `/enrollments/:id` | Admin / docente propietario del curso | Elimina inscripción |
| `GET` | `/attendance?course_id=...&fecha=...` | Admin / docente | Asistencia de un curso en una fecha |
| `POST` | `/attendance` | Admin / docente | Guarda asistencia por lote |

### Parámetros del historial

`GET /api/courses/:id/history` acepta:

| Parámetro | Descripción |
| --- | --- |
| `desde` | Fecha inicial inclusive (`YYYY-MM-DD`) |
| `hasta` | Fecha final inclusive (`YYYY-MM-DD`) |
| `limit` | Registros por página; por defecto 100, máximo 500 |
| `offset` | Desplazamiento para paginación |

Respuesta:

```json
{
  "items": [
    {
      "nombre": "Ana Pérez",
      "fecha": "2026-10-24",
      "estado": "presente",
      "origen": "manual",
      "marcado_por_nombre": "Carlos Ruiz",
      "updated_at": "2026-10-24 12:30:00"
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

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

### Códigos de estado habituales

| Código | Significado |
| --- | --- |
| `200` | Operación correcta |
| `400` | Datos inválidos |
| `401` | Sesión ausente, vencida o revocada |
| `403` | Sin permisos, código de invitación incorrecto o registro deshabilitado |
| `404` | Recurso no encontrado |
| `429` | Demasiados intentos; incluye `Retry-After` |
| `500` | Error interno (sin detalles sensibles) |

---

## Modelo de datos

| Tabla | Descripción | Campos principales |
| --- | --- | --- |
| `courses` | Cursos | `id`, `nombre`, `descripcion`, `teacher_id`, `activo`, `created_at` |
| `students` | Estudiantes | `id`, `nombre`, `documento`, `email`, `telefono`, `password_hash`, `salt`, `teacher_id`, `activo`, `session_version` |
| `teachers` | Docentes | `id`, `nombre`, `email`, `password_hash`, `salt`, `session_version` |
| `enrollments` | Inscripciones | `id`, `student_id`, `course_id` |
| `attendance` | Asistencia | `id`, `enrollment_id`, `fecha`, `estado`, `origen`, `marcado_por_rol`, `marcado_por_id`, `marcado_por_nombre`, `updated_at` |
| `attendance_audit` | Auditoría de asistencia | `id`, `enrollment_id`, `course_id`, `fecha`, `estado_anterior`, `estado_nuevo`, `origen`, `actor_rol`, `actor_id`, `actor_nombre`, `created_at` |
| `rate_limits` | Control de intentos | `key`, `window_start`, `count` |

Restricciones y convenciones relevantes:

- `students.documento` es único.
- `teachers.email` es único.
- `teacher_id = NULL` significa registro institucional/compartido.
- `activo = 0` significa archivado; el registro se conserva.
- Un estudiante no puede inscribirse dos veces en el mismo curso.
- Solo puede existir un registro de asistencia por inscripción y fecha.
- `attendance.estado` acepta únicamente `presente`, `ausente`, `tarde` o `justificado`.
- Al eliminar un docente, sus cursos y estudiantes pasan a ser institucionales (`ON DELETE SET NULL`).
- Las inscripciones y asistencias se eliminan en cascada solo si se borra físicamente un curso o un estudiante; la aplicación usa archivado lógico.

---

## Seguridad

### Controles implementados

- Contraseñas derivadas con **PBKDF2-SHA256**, salt aleatorio y 100 000 iteraciones.
- Sesiones y tokens QR firmados con **HMAC-SHA256**.
- Expiración de sesiones y códigos QR.
- Cookie de administrador `HttpOnly`, `SameSite=Strict` y `Secure` en HTTPS.
- Revocación de sesiones de docentes y estudiantes mediante `session_version`.
- Separación de permisos por rol y por docente propietario.
- Rechazo de estudiantes archivados en login, registro y canje de QR.
- Validación estricta de fechas (`YYYY-MM-DD`) y de estados de asistencia.
- Límite de 300 registros por lote de asistencia y 500 por consulta de historial.
- Rate limiting por IP en inicios de sesión y registros.
- Validación de origen (`Origin`) en solicitudes que modifican datos.
- Auditoría de cada cambio de asistencia.
- Respuestas de error internas genéricas; los detalles se registran en el Worker.
- Variables sensibles gestionadas mediante secretos de Wrangler.

### Consideraciones

- La aplicación usa **una única clave de administrador**. No existe un sistema de usuarios administradores con roles internos.
- El rate limiting se apoya en la tabla `rate_limits`; si la migración 003 no está aplicada, el sistema falla abierto para no bloquear el acceso.
- Los tokens firmados de docentes y estudiantes se revocan al cambiar o restablecer la contraseña; el token del administrador expira con la cookie.
- El panel administrativo sigue siendo accesible desde Internet; para datos sensibles se recomienda **Cloudflare Access**.
- Los QR de inscripción siguen siendo válidos durante 7 días; si se filtran, cualquier persona con el enlace podría inscribirse.
- El registro público de docentes está deshabilitado salvo que configures `CODIGO_DOCENTE`.

Para un entorno con datos sensibles se recomienda:

1. Publicar el Worker detrás de **Cloudflare Access**.
2. Configurar reglas adicionales de **rate limiting** en Cloudflare.
3. Usar contraseñas largas y rotar `API_KEY` y `SESSION_SECRET` periódicamente.
4. Mantener `CODIGO_DOCENTE` configurado solo si necesitas registro público de docentes.
5. Realizar respaldos antes de cada cambio importante.

---

## Respaldos y migraciones

### Crear un respaldo

```bash
wrangler d1 export asistencia_db --remote --output=backup-asistencia.sql
```

Guarda el archivo en un lugar seguro y fuera del repositorio.

### Aplicar cambios al esquema

- `schema.sql` describe el esquema completo y se usa en instalaciones nuevas.
- `migration_003_seguridad_y_alcance.sql` actualiza bases existentes de forma aditiva.
- No apliques ambas cosas sobre la misma base: usa `schema.sql` para una base vacía o `migration_003` para una base con datos.
- Antes de aplicar una migración en producción, crea un respaldo.
- La migración 003 se probó sobre una base con el esquema anterior y datos existentes; conserva cursos, estudiantes, inscripciones y asistencia, y añade valores por defecto (`activo = 1`, `origen = 'manual'`, `session_version = 1`).

### Actualizar la aplicación

```bash
wrangler deploy
```

La base de datos y los datos existentes no se modifican al desplegar una nueva versión del Worker.

---

## Buenas prácticas y mejoras recomendadas

Estas mejoras no están implementadas y pueden evaluarse según el alcance del proyecto:

- **Aprobación de inscripciones:** requerir confirmación del docente cuando un estudiante se inscribe por QR.
- **Usuarios administradores:** sustituir la clave única por cuentas con roles y auditoría propios.
- **Cloudflare Access:** restringir el panel administrativo a correos o dominios autorizados.
- **Notificaciones:** avisar por email cuando se restablece una contraseña o se archiva una cuenta.
- **Reportes exportables:** generar CSV/PDF del historial por curso o estudiante.
- **Pruebas automatizadas:** añadir pruebas de integración para la API y de extremo a extremo para el frontend.
- **Múltiples instituciones:** incorporar un identificador de institución si el sistema se comparte entre organizaciones.

---

## Licencia y uso

Proyecto de uso interno para gestión académica. Ajusta la licencia y las condiciones de uso según las necesidades de tu institución antes de distribuirlo públicamente.

El generador de QR incluido en `src/qrcode.mjs` es una versión vendorizada de [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator), distribuida bajo licencia MIT.
