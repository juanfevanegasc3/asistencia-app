// ==========================================================
// Sistema de Asistencia - Cloudflare Worker + D1
// ==========================================================

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function isAuthorized(request, env) {
  const key = request.headers.get("X-API-Key");
  return key && env.API_KEY && key === env.API_KEY;
}

async function handleApi(request, env, url) {
  const path = url.pathname.replace(/^\/api/, "");
  const method = request.method;

  // Login (solo valida la clave)
  if (path === "/login" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    if (body.apiKey === env.API_KEY) return json({ ok: true });
    return json({ ok: false, error: "Clave incorrecta" }, 401);
  }

  // A partir de aquí, todo requiere autorización
  if (!isAuthorized(request, env)) {
    return json({ error: "No autorizado" }, 401);
  }

  // ---------- CURSOS ----------
  if (path === "/courses" && method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT * FROM courses ORDER BY nombre"
    ).all();
    return json(results);
  }
  if (path === "/courses" && method === "POST") {
    const b = await request.json();
    if (!b.nombre) return json({ error: "Falta el nombre del curso" }, 400);
    const r = await env.DB.prepare(
      "INSERT INTO courses (nombre, descripcion) VALUES (?, ?)"
    ).bind(b.nombre, b.descripcion || null).run();
    return json({ id: r.meta.last_row_id });
  }
  const courseIdMatch = path.match(/^\/courses\/(\d+)$/);
  if (courseIdMatch && method === "DELETE") {
    await env.DB.prepare("DELETE FROM courses WHERE id = ?")
      .bind(courseIdMatch[1]).run();
    return json({ ok: true });
  }

  // ---------- ESTUDIANTES ----------
  if (path === "/students" && method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT * FROM students ORDER BY nombre"
    ).all();
    return json(results);
  }
  if (path === "/students" && method === "POST") {
    const b = await request.json();
    if (!b.nombre) return json({ error: "Falta el nombre del estudiante" }, 400);
    try {
      const r = await env.DB.prepare(
        "INSERT INTO students (nombre, documento, email, telefono) VALUES (?, ?, ?, ?)"
      ).bind(b.nombre, b.documento || null, b.email || null, b.telefono || null).run();
      return json({ id: r.meta.last_row_id });
    } catch (e) {
      return json({ error: "Ese documento ya está registrado" }, 400);
    }
  }
  const studentIdMatch = path.match(/^\/students\/(\d+)$/);
  if (studentIdMatch && method === "DELETE") {
    await env.DB.prepare("DELETE FROM students WHERE id = ?")
      .bind(studentIdMatch[1]).run();
    return json({ ok: true });
  }

  // ---------- INSCRIPCIONES ----------
  if (path === "/enrollments" && method === "POST") {
    const b = await request.json();
    try {
      const r = await env.DB.prepare(
        "INSERT INTO enrollments (student_id, course_id) VALUES (?, ?)"
      ).bind(b.student_id, b.course_id).run();
      return json({ id: r.meta.last_row_id });
    } catch (e) {
      return json({ error: "El estudiante ya está inscrito en ese curso" }, 400);
    }
  }
  const enrollDeleteMatch = path.match(/^\/enrollments\/(\d+)$/);
  if (enrollDeleteMatch && method === "DELETE") {
    await env.DB.prepare("DELETE FROM enrollments WHERE id = ?")
      .bind(enrollDeleteMatch[1]).run();
    return json({ ok: true });
  }
  const courseStudentsMatch = path.match(/^\/courses\/(\d+)\/students$/);
  if (courseStudentsMatch && method === "GET") {
    const { results } = await env.DB.prepare(
      `SELECT e.id AS enrollment_id, s.id AS student_id, s.nombre, s.documento
       FROM enrollments e JOIN students s ON s.id = e.student_id
       WHERE e.course_id = ? ORDER BY s.nombre`
    ).bind(courseStudentsMatch[1]).all();
    return json(results);
  }

  // ---------- ASISTENCIA ----------
  // Guarda o actualiza asistencia en lote para un curso y fecha
  if (path === "/attendance" && method === "POST") {
    const b = await request.json(); // { fecha, registros: [{enrollment_id, estado}] }
    if (!b.fecha || !Array.isArray(b.registros)) {
      return json({ error: "Datos incompletos" }, 400);
    }
    const stmts = b.registros.map((r) =>
      env.DB.prepare(
        `INSERT INTO attendance (enrollment_id, fecha, estado)
         VALUES (?, ?, ?)
         ON CONFLICT(enrollment_id, fecha) DO UPDATE SET estado = excluded.estado`
      ).bind(r.enrollment_id, b.fecha, r.estado)
    );
    if (stmts.length) await env.DB.batch(stmts);
    return json({ ok: true, guardados: stmts.length });
  }

  // Trae asistencia de un curso en una fecha específica
  if (path === "/attendance" && method === "GET") {
    const courseId = url.searchParams.get("course_id");
    const fecha = url.searchParams.get("fecha");
    if (!courseId || !fecha) return json({ error: "Falta course_id o fecha" }, 400);
    const { results } = await env.DB.prepare(
      `SELECT e.id AS enrollment_id, s.nombre, s.documento, a.estado
       FROM enrollments e
       JOIN students s ON s.id = e.student_id
       LEFT JOIN attendance a ON a.enrollment_id = e.id AND a.fecha = ?
       WHERE e.course_id = ? ORDER BY s.nombre`
    ).bind(fecha, courseId).all();
    return json(results);
  }

  // Historial de asistencia de un curso (todas las fechas)
  const historyMatch = path.match(/^\/courses\/(\d+)\/history$/);
  if (historyMatch && method === "GET") {
    const { results } = await env.DB.prepare(
      `SELECT s.nombre, a.fecha, a.estado
       FROM attendance a
       JOIN enrollments e ON e.id = a.enrollment_id
       JOIN students s ON s.id = e.student_id
       WHERE e.course_id = ?
       ORDER BY a.fecha DESC, s.nombre`
    ).bind(historyMatch[1]).all();
    return json(results);
  }

  return json({ error: "Ruta no encontrada" }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try {
        return await handleApi(request, env, url);
      } catch (err) {
        return json({ error: "Error interno", detalle: String(err) }, 500);
      }
    }
    return new Response(HTML_PAGE, {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  },
};

// ==========================================================
// FRONTEND (HTML + CSS + JS embebido)
// ==========================================================
const HTML_PAGE = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Asistencia de Cursos</title>
<style>
  :root{
    --bg:#f7f7f9; --card:#fff; --text:#1a1a2e; --muted:#6b7280;
    --accent:#4f46e5; --accent-dark:#4338ca; --border:#e5e7eb;
    --ok:#16a34a; --warn:#d97706; --bad:#dc2626;
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--text)}
  header{background:var(--accent);color:#fff;padding:18px 20px;font-size:20px;font-weight:700}
  .wrap{max-width:960px;margin:0 auto;padding:20px}
  nav{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}
  nav button{padding:10px 16px;border:1px solid var(--border);background:var(--card);border-radius:8px;cursor:pointer;font-weight:600;color:var(--muted)}
  nav button.active{background:var(--accent);color:#fff;border-color:var(--accent)}
  .card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:16px}
  h2{margin-top:0;font-size:17px}
  input,select{padding:9px 10px;border:1px solid var(--border);border-radius:8px;font-size:14px;width:100%}
  label{font-size:12px;color:var(--muted);display:block;margin-bottom:4px;font-weight:600}
  .field{margin-bottom:12px}
  .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  button.primary{background:var(--accent);color:#fff;border:none;padding:10px 18px;border-radius:8px;font-weight:700;cursor:pointer}
  button.primary:hover{background:var(--accent-dark)}
  button.danger{background:none;border:1px solid var(--bad);color:var(--bad);padding:6px 10px;border-radius:6px;cursor:pointer;font-size:12px}
  table{width:100%;border-collapse:collapse;margin-top:10px}
  th,td{text-align:left;padding:8px;border-bottom:1px solid var(--border);font-size:14px}
  th{color:var(--muted);font-size:12px;text-transform:uppercase}
  .estado-btns{display:flex;gap:4px}
  .estado-btns button{flex:1;padding:6px 4px;font-size:12px;border-radius:6px;border:1px solid var(--border);background:#fff;cursor:pointer}
  .estado-btns button.sel-presente{background:#dcfce7;border-color:var(--ok);color:var(--ok)}
  .estado-btns button.sel-ausente{background:#fee2e2;border-color:var(--bad);color:var(--bad)}
  .estado-btns button.sel-tarde{background:#fef3c7;border-color:var(--warn);color:var(--warn)}
  .estado-btns button.sel-justificado{background:#e0e7ff;border-color:var(--accent);color:var(--accent)}
  .muted{color:var(--muted);font-size:13px}
  #loginScreen{max-width:360px;margin:80px auto;text-align:center}
  .hidden{display:none}
  .msg{font-size:13px;margin-top:8px}
  .msg.ok{color:var(--ok)} .msg.bad{color:var(--bad)}
</style>
</head>
<body>

<div id="loginScreen" class="card">
  <h2>🔑 Acceso</h2>
  <p class="muted">Ingresa la clave de acceso configurada en el Worker.</p>
  <div class="field"><input id="apiKeyInput" type="password" placeholder="Clave de acceso"></div>
  <button class="primary" onclick="login()" style="width:100%">Entrar</button>
  <div id="loginMsg" class="msg"></div>
</div>

<div id="app" class="hidden">
  <header>📋 Sistema de Asistencia</header>
  <div class="wrap">
    <nav>
      <button data-tab="cursos" class="active">Cursos</button>
      <button data-tab="estudiantes">Estudiantes</button>
      <button data-tab="inscripciones">Inscripciones</button>
      <button data-tab="asistencia">Tomar Asistencia</button>
      <button data-tab="historial">Historial</button>
    </nav>

    <section id="tab-cursos">
      <div class="card">
        <h2>Nuevo curso</h2>
        <div class="row">
          <div class="field"><label>Nombre</label><input id="cursoNombre" placeholder="Ej. Matemáticas 10A"></div>
          <div class="field"><label>Descripción (opcional)</label><input id="cursoDesc"></div>
        </div>
        <button class="primary" onclick="crearCurso()">Agregar curso</button>
      </div>
      <div class="card">
        <h2>Cursos registrados</h2>
        <table><thead><tr><th>Nombre</th><th>Descripción</th><th></th></tr></thead>
          <tbody id="listaCursos"></tbody></table>
      </div>
    </section>

    <section id="tab-estudiantes" class="hidden">
      <div class="card">
        <h2>Nuevo estudiante</h2>
        <div class="row">
          <div class="field"><label>Nombre completo</label><input id="estNombre"></div>
          <div class="field"><label>Documento</label><input id="estDoc"></div>
        </div>
        <div class="row">
          <div class="field"><label>Email (opcional)</label><input id="estEmail"></div>
          <div class="field"><label>Teléfono (opcional)</label><input id="estTel"></div>
        </div>
        <button class="primary" onclick="crearEstudiante()">Agregar estudiante</button>
      </div>
      <div class="card">
        <h2>Estudiantes registrados</h2>
        <table><thead><tr><th>Nombre</th><th>Documento</th><th>Email</th><th></th></tr></thead>
          <tbody id="listaEstudiantes"></tbody></table>
      </div>
    </section>

    <section id="tab-inscripciones" class="hidden">
      <div class="card">
        <h2>Inscribir estudiante a un curso</h2>
        <div class="row">
          <div class="field"><label>Curso</label><select id="inscCurso"></select></div>
          <div class="field"><label>Estudiante</label><select id="inscEstudiante"></select></div>
        </div>
        <button class="primary" onclick="inscribir()">Inscribir</button>
        <div id="inscMsg" class="msg"></div>
      </div>
      <div class="card">
        <h2>Estudiantes por curso</h2>
        <div class="field"><label>Selecciona un curso</label><select id="verCurso" onchange="cargarInscritos()"></select></div>
        <table><thead><tr><th>Nombre</th><th>Documento</th><th></th></tr></thead>
          <tbody id="listaInscritos"></tbody></table>
      </div>
    </section>

    <section id="tab-asistencia" class="hidden">
      <div class="card">
        <h2>Tomar asistencia</h2>
        <div class="row">
          <div class="field"><label>Curso</label><select id="asisCurso" onchange="cargarAsistencia()"></select></div>
          <div class="field"><label>Fecha</label><input type="date" id="asisFecha" onchange="cargarAsistencia()"></div>
        </div>
        <table><thead><tr><th>Estudiante</th><th style="width:260px">Estado</th></tr></thead>
          <tbody id="listaAsistencia"></tbody></table>
        <button class="primary" onclick="guardarAsistencia()" style="margin-top:12px">Guardar asistencia</button>
        <div id="asisMsg" class="msg"></div>
      </div>
    </section>

    <section id="tab-historial" class="hidden">
      <div class="card">
        <h2>Historial de asistencia</h2>
        <div class="field"><label>Curso</label><select id="histCurso" onchange="cargarHistorial()"></select></div>
        <table><thead><tr><th>Estudiante</th><th>Fecha</th><th>Estado</th></tr></thead>
          <tbody id="listaHistorial"></tbody></table>
      </div>
    </section>
  </div>
</div>

<script>
let API_KEY = localStorage.getItem('asistencia_key') || '';
let courses = [], students = [];
const estados = ['presente','ausente','tarde','justificado'];

async function api(path, opts = {}) {
  const res = await fetch('/api' + path, {
    ...opts,
    headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY, ...(opts.headers||{}) }
  });
  if (res.status === 401) { showLogin('Sesión inválida, ingresa de nuevo.'); throw new Error('401'); }
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Error');
  return data;
}

function showLogin(msg) {
  document.getElementById('app').classList.add('hidden');
  document.getElementById('loginScreen').classList.remove('hidden');
  if (msg) { document.getElementById('loginMsg').textContent = msg; document.getElementById('loginMsg').className='msg bad'; }
}

async function login() {
  const key = document.getElementById('apiKeyInput').value;
  const res = await fetch('/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({apiKey:key}) });
  const data = await res.json();
  if (data.ok) {
    API_KEY = key; localStorage.setItem('asistencia_key', key);
    document.getElementById('loginScreen').classList.add('hidden');
    document.getElementById('app').classList.remove('hidden');
    initApp();
  } else {
    document.getElementById('loginMsg').textContent = 'Clave incorrecta';
    document.getElementById('loginMsg').className = 'msg bad';
  }
}

document.querySelectorAll('nav button').forEach(btn => {
  btn.onclick = () => {
    document.querySelectorAll('nav button').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('section').forEach(s=>s.classList.add('hidden'));
    document.getElementById('tab-'+btn.dataset.tab).classList.remove('hidden');
  };
});

async function initApp() {
  document.getElementById('asisFecha').value = new Date().toISOString().slice(0,10);
  await Promise.all([cargarCursos(), cargarEstudiantes()]);
}

// ---- Cursos ----
async function cargarCursos() {
  courses = await api('/courses');
  document.getElementById('listaCursos').innerHTML = courses.map(c =>
    \`<tr><td>\${c.nombre}</td><td class="muted">\${c.descripcion||''}</td>
     <td><button class="danger" onclick="borrarCurso(\${c.id})">Eliminar</button></td></tr>\`
  ).join('') || '<tr><td class="muted" colspan="3">Sin cursos aún</td></tr>';
  const opts = courses.map(c => \`<option value="\${c.id}">\${c.nombre}</option>\`).join('');
  ['inscCurso','verCurso','asisCurso','histCurso'].forEach(id => document.getElementById(id).innerHTML = opts);
}
async function crearCurso() {
  const nombre = document.getElementById('cursoNombre').value.trim();
  if (!nombre) return alert('Escribe un nombre de curso');
  await api('/courses', { method:'POST', body: JSON.stringify({ nombre, descripcion: document.getElementById('cursoDesc').value }) });
  document.getElementById('cursoNombre').value=''; document.getElementById('cursoDesc').value='';
  await cargarCursos();
}
async function borrarCurso(id) {
  if (!confirm('¿Eliminar este curso y sus inscripciones/asistencia?')) return;
  await api('/courses/'+id, { method:'DELETE' }); await cargarCursos();
}

// ---- Estudiantes ----
async function cargarEstudiantes() {
  students = await api('/students');
  document.getElementById('listaEstudiantes').innerHTML = students.map(s =>
    \`<tr><td>\${s.nombre}</td><td class="muted">\${s.documento||''}</td><td class="muted">\${s.email||''}</td>
     <td><button class="danger" onclick="borrarEstudiante(\${s.id})">Eliminar</button></td></tr>\`
  ).join('') || '<tr><td class="muted" colspan="4">Sin estudiantes aún</td></tr>';
  document.getElementById('inscEstudiante').innerHTML = students.map(s => \`<option value="\${s.id}">\${s.nombre}</option>\`).join('');
}
async function crearEstudiante() {
  const nombre = document.getElementById('estNombre').value.trim();
  if (!nombre) return alert('Escribe el nombre del estudiante');
  try {
    await api('/students', { method:'POST', body: JSON.stringify({
      nombre, documento: document.getElementById('estDoc').value,
      email: document.getElementById('estEmail').value, telefono: document.getElementById('estTel').value
    })});
    ['estNombre','estDoc','estEmail','estTel'].forEach(id=>document.getElementById(id).value='');
    await cargarEstudiantes();
  } catch(e) { alert(e.message); }
}
async function borrarEstudiante(id) {
  if (!confirm('¿Eliminar este estudiante?')) return;
  await api('/students/'+id, { method:'DELETE' }); await cargarEstudiantes();
}

// ---- Inscripciones ----
async function inscribir() {
  const course_id = document.getElementById('inscCurso').value;
  const student_id = document.getElementById('inscEstudiante').value;
  const msgEl = document.getElementById('inscMsg');
  try {
    await api('/enrollments', { method:'POST', body: JSON.stringify({ course_id, student_id }) });
    msgEl.textContent = 'Inscrito correctamente'; msgEl.className='msg ok';
    if (document.getElementById('verCurso').value === course_id) cargarInscritos();
  } catch(e) { msgEl.textContent = e.message; msgEl.className='msg bad'; }
}
async function cargarInscritos() {
  const courseId = document.getElementById('verCurso').value;
  if (!courseId) return;
  const list = await api('/courses/'+courseId+'/students');
  document.getElementById('listaInscritos').innerHTML = list.map(s =>
    \`<tr><td>\${s.nombre}</td><td class="muted">\${s.documento||''}</td>
     <td><button class="danger" onclick="quitarInscripcion(\${s.enrollment_id})">Quitar</button></td></tr>\`
  ).join('') || '<tr><td class="muted" colspan="3">Nadie inscrito todavía</td></tr>';
}
async function quitarInscripcion(id) {
  await api('/enrollments/'+id, { method:'DELETE' }); await cargarInscritos();
}

// ---- Asistencia ----
async function cargarAsistencia() {
  const courseId = document.getElementById('asisCurso').value;
  const fecha = document.getElementById('asisFecha').value;
  if (!courseId || !fecha) return;
  const list = await api('/attendance?course_id='+courseId+'&fecha='+fecha);
  document.getElementById('listaAsistencia').innerHTML = list.map(r => \`
    <tr data-enrollment="\${r.enrollment_id}">
      <td>\${r.nombre}</td>
      <td><div class="estado-btns">
        \${estados.map(e => \`<button class="\${r.estado===e?'sel-'+e:''}" onclick="marcar(this,\${r.enrollment_id},'\${e}')">\${e}</button>\`).join('')}
      </div></td>
    </tr>\`).join('') || '<tr><td class="muted" colspan="2">Este curso no tiene estudiantes inscritos</td></tr>';
}
function marcar(btn, enrollmentId, estado) {
  const row = btn.closest('tr');
  row.querySelectorAll('button').forEach(b => b.className = '');
  btn.className = 'sel-'+estado;
  row.dataset.estado = estado;
}
async function guardarAsistencia() {
  const fecha = document.getElementById('asisFecha').value;
  const rows = [...document.querySelectorAll('#listaAsistencia tr[data-enrollment]')];
  const registros = rows.filter(r => r.dataset.estado).map(r => ({ enrollment_id: r.dataset.enrollment, estado: r.dataset.estado }));
  const msgEl = document.getElementById('asisMsg');
  if (!registros.length) { msgEl.textContent='Marca al menos un estado'; msgEl.className='msg bad'; return; }
  try {
    await api('/attendance', { method:'POST', body: JSON.stringify({ fecha, registros }) });
    msgEl.textContent = 'Asistencia guardada ✓'; msgEl.className='msg ok';
  } catch(e) { msgEl.textContent = e.message; msgEl.className='msg bad'; }
}

// ---- Historial ----
async function cargarHistorial() {
  const courseId = document.getElementById('histCurso').value;
  if (!courseId) return;
  const list = await api('/courses/'+courseId+'/history');
  document.getElementById('listaHistorial').innerHTML = list.map(r =>
    \`<tr><td>\${r.nombre}</td><td>\${r.fecha}</td><td>\${r.estado}</td></tr>\`
  ).join('') || '<tr><td class="muted" colspan="3">Sin registros aún</td></tr>';
}

// Auto-login si ya hay clave guardada
if (API_KEY) {
  fetch('/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({apiKey:API_KEY}) })
    .then(r=>r.json()).then(d => {
      if (d.ok) { document.getElementById('loginScreen').classList.add('hidden'); document.getElementById('app').classList.remove('hidden'); initApp(); }
    });
}
</script>
</body>
</html>`;
