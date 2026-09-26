# Sistema de Asistencia — Cloudflare Workers + D1

Todo se despliega **gratis** en tu cuenta de Cloudflare: el Worker (backend + página web)
y la base de datos D1 (SQL) para guardar estudiantes y asistencia.

## Requisitos
- Cuenta gratuita en https://dash.cloudflare.com (regístrate si no tienes)
- Node.js instalado en tu computador (https://nodejs.org)

## Pasos para desplegar

### 1. Instalar Wrangler (herramienta de Cloudflare)
Abre una terminal dentro de esta carpeta (`asistencia-app`) y ejecuta:

```bash
npm install -g wrangler
wrangler login
```

Esto abrirá tu navegador para conectar Wrangler con tu cuenta de Cloudflare.

### 2. Crear la base de datos D1

```bash
wrangler d1 create asistencia_db
```

Esto te devuelve algo como:

```
[[d1_databases]]
binding = "DB"
database_name = "asistencia_db"
database_id = "1a2b3c4d-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

Copia ese `database_id` y pégalo en el archivo `wrangler.toml`, reemplazando
`PON_AQUI_TU_DATABASE_ID`.

### 3. Crear las tablas en la base de datos

```bash
wrangler d1 execute asistencia_db --remote --file=./schema.sql
```

### 4. Cambiar la clave de acceso

Abre `wrangler.toml` y cambia:

```toml
[vars]
API_KEY = "cambia-esta-clave-1234"
```

por una clave tuya (será la "contraseña" para entrar a la página). Guárdala en un lugar seguro.

### 5. Desplegar

```bash
wrangler deploy
```

Al terminar te dará una URL como `https://asistencia-app.tu-usuario.workers.dev`.
¡Esa es tu página! Ábrela, ingresa la clave que configuraste, y ya puedes:

- Registrar cursos
- Registrar estudiantes
- Inscribir estudiantes a cursos
- Tomar asistencia por fecha
- Ver el historial de asistencia por curso

## Actualizar la página más adelante
Si quieres modificar algo del código (`src/index.js`), solo vuelve a correr:

```bash
wrangler deploy
```

## Notas sobre el plan gratuito de Cloudflare
- **Workers (gratis):** 100,000 solicitudes/día — de sobra para tomar asistencia.
- **D1 (gratis):** 5 GB de almacenamiento y 5 millones de lecturas/día — más que suficiente
  para cientos de cursos y miles de estudiantes.
- No necesitas tarjeta de crédito para el plan gratuito de Workers + D1.

## Seguridad
Esta app usa una clave de acceso simple (todos los que la tengan pueden editar los datos).
Es suficiente para uso interno de un profesor o institución pequeña. Si necesitas que cada
usuario tenga su propio usuario y contraseña, o permisos distintos, se puede ampliar más
adelante — solo dime.
