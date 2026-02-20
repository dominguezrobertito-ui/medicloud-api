require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();

// Azure App Service va detrás de proxy
app.set('trust proxy', 1);

// Quita header de Express
app.disable('x-powered-by');

// Cabeceras de seguridad
app.use(
  helmet({
    // CSP mínima "segura" para una API (no rompe JSON)
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        baseUri: ["'none'"],
        frameAncestors: ["'none'"], // anti-clickjacking vía CSP
        formAction: ["'none'"],
      },
    },
    // Si sirves PDFs/archivos, esto a veces molesta; lo desactivamos:
    crossOriginEmbedderPolicy: false,
  })
);

// Anti-clickjacking "clásico" (ZAP lo suele exigir)
app.use(helmet.frameguard({ action: 'deny' }));

/* =========================
   CORS + JSON + Cache
   ========================= */
// ✅ CORS dinámico por variable de entorno (CSV)
const allowedOrigins = (process.env.CORS_ORIGIN || 'http://localhost:4200')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error(`Not allowed by CORS: ${origin}`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

app.options(/.*/, cors(corsOptions));
app.use(cors(corsOptions));

app.use((err, _req, res, next) => {
  if (err && String(err.message || '').startsWith('Not allowed by CORS')) {
    return res.status(403).json({ error: 'CORS blocked' });
  }
  next(err);
});

app.use(express.json());

app.disable('etag');
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

/* =========================
   ENV
   ========================= */
const {
  PORT = 3000,
  DB_HOST,
  DB_PORT,
  DB_USER,
  DB_PASSWORD,
  DB_NAME,
  JWT_SECRET,
  STORAGE_DIR,

  CONTACT_TO,
  SMTP_HOST,
  SMTP_PORT,
  SMTP_SECURE,
  SMTP_USER,
  SMTP_PASS,
} = process.env;

console.log('JWT_SECRET loaded?', !!JWT_SECRET);

/* =========================
   Storage directory
   ========================= */
const STORAGE_PATH = STORAGE_DIR || path.join(__dirname, 'storage');
fs.mkdirSync(STORAGE_PATH, { recursive: true });

// Servir estático para abrir en navegador (dev)
app.use(
  '/storage',
  express.static(STORAGE_PATH, {
    etag: false,
    maxAge: 0,
  })
);

/* =========================
   DB pool
   ========================= */
const pool = mysql.createPool({
  host: DB_HOST,
  port: Number(DB_PORT),
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,

  // ✅ Azure MySQL suele requerir SSL
  ssl: String(process.env.DB_SSL || 'true') === 'true'
    ? { rejectUnauthorized: true }
    : undefined,
});

// SMTP transporter (si se proporcionan credenciales)
const mailTransport =
  SMTP_USER && SMTP_PASS
    ? nodemailer.createTransport({
        host: SMTP_HOST || 'smtp.gmail.com',
        port: Number(SMTP_PORT || 465),
        secure: String(SMTP_SECURE || 'true') === 'true',
        auth: { user: SMTP_USER, pass: SMTP_PASS },
      })
    : null;

if (!mailTransport) {
  console.warn('[MAIL] SMTP no configurado (SMTP_USER/SMTP_PASS). /contact devolverá error.');
}

// Rate limiter para /contact
const contactLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 min
  max: 5, // 5 envíos / 10 min / IP
  standardHeaders: true,
  legacyHeaders: false,
});

function dbError(res, e, fallback = 'Database error') {
  console.error('DB ERROR:', e);
  return res.status(500).json({
    error: fallback,
    code: e.code || null,
    sqlMessage: e.sqlMessage || null,
    detail: e.message || null,
  });
}

/* =========================
   JWT helpers
   ========================= */
function signToken(user) {
  return jwt.sign(
    { sub: user.id_cuenta, email: user.correo, role: user.tipo_cuenta },
    JWT_SECRET,
    { expiresIn: '2h' }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token', detail: String(e) });
  }
}

async function logEvent({
  id_cuenta,
  tipo_evento,
  ip_origen,
  resultado,
  detalle,
  id_archivo = null,
  id_factura = null,
}) {
  try {
    await pool.execute(
      `INSERT INTO evento_seguridad (id_cuenta, id_archivo, id_factura, tipo_evento, ip_origen, resultado, detalle)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [id_cuenta, id_archivo, id_factura, tipo_evento, ip_origen, resultado || null, detalle || null]
    );
  } catch (e) {
    console.warn('[logEvent] warn:', e.code, e.sqlMessage);
  }
}

/* =========================
   Roles / Tenants helpers
   =========================
   - Paciente:      tipo_cuenta = CLIENTE, id_empresa != NULL
   - Empleado hospital: tipo_cuenta = TRABAJADOR, id_empresa != NULL
   - Empleado MediCloud: tipo_cuenta = TRABAJADOR o ADMIN, id_empresa == NULL
*/
function isStaffRole(role) {
  role = String(role || '').toUpperCase();
  return role === 'TRABAJADOR' || role === 'ADMIN';
}

async function getUserCtx(userId) {
  const [rows] = await pool.execute(
    `SELECT id_cuenta, correo, tipo_cuenta, estado, origen_autenticacion, id_empresa
     FROM cuenta
     WHERE id_cuenta = ? LIMIT 1`,
    [userId]
  );
  return rows[0] || null;
}

function isHospitalWorker(ctx) {
  return ctx && String(ctx.tipo_cuenta).toUpperCase() === 'TRABAJADOR' && ctx.id_empresa != null;
}

function isMediCloudWorker(ctx) {
  if (!ctx) return false;
  const role = String(ctx.tipo_cuenta).toUpperCase();
  if (role === 'ADMIN') return true;
  return role === 'TRABAJADOR' && (ctx.id_empresa == null);
}

function requireAdmin(req, res, next) {
  const role = String(req.user?.role || '').toUpperCase();
  if (role !== 'ADMIN') return res.status(403).json({ error: 'Forbidden' });
  next();
}

/* =========================
   Multer upload config (PDF)
   ========================= */
const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, STORAGE_PATH),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname || '').toLowerCase();
      const safeExt = ext === '.pdf' ? ext : '';
      const unique = `${Date.now()}_${crypto.randomBytes(8).toString('hex')}${safeExt}`;
      cb(null, unique);
    },
  }),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (_req, file, cb) => {
    const okMime = file.mimetype === 'application/pdf';
    const okExt = (file.originalname || '').toLowerCase().endsWith('.pdf');
    if (!okMime || !okExt) return cb(new Error('Solo se permite PDF'));
    cb(null, true);
  },
});

function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (d) => h.update(d));
    stream.on('end', () => resolve(h.digest('hex')));
    stream.on('error', reject);
  });
}

/* =========================
   Normalizers
   ========================= */
function normalizeEstado(v) {
  return v ? String(v).trim().toUpperCase() : null;
}
function normalizePrioridad(v) {
  return v ? String(v).trim().toUpperCase() : null;
}

/* =========================
   ROUTES
   ========================= */

app.get('/health', async (_req, res) => {
  try {
    const [r] = await pool.query('SELECT 1 AS ok');
    res.json({ status: 'ok', db: r[0].ok });
  } catch (e) {
    res.status(500).json({ status: 'error', error: String(e) });
  }
});

app.get('/debug/secret', (_req, res) => {
  res.json({ hasSecret: !!JWT_SECRET, len: (JWT_SECRET || '').length });
});

/* =========================
   AUTH
   ========================= */
const MAX_FAILED = 5;
const LOCK_MINUTES = 15;

function normEmail(s) {
  return String(s || '').trim().toLowerCase();
}

function isStrongPassword(pw) {
  return /^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/.test(pw);
}

app.post('/auth/login', async (req, res) => {
  const email = normEmail(req.body?.email);
  const password = String(req.body?.password || '');
  const ip = req.ip;

  if (!email || !password) {
    return res.status(400).json({ error: 'email y password required' });
  }

  try {
    const [rows] = await pool.execute(
      `
      SELECT
        c.id_cuenta, c.correo, c.tipo_cuenta, c.estado, c.origen_autenticacion,
        c.id_empresa,
        cr.password_hash, cr.requiere_reset, cr.intentos_fallidos, cr.bloqueo_hasta
      FROM cuenta c
      LEFT JOIN credencial cr ON cr.id_cuenta = c.id_cuenta
      WHERE c.correo = ?
      LIMIT 1
      `,
      [email]
    );

    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Credenciales inválidas' });

    if (user.estado !== 'ACTIVA') {
      await logEvent({
        id_cuenta: user.id_cuenta,
        tipo_evento: 'LOGIN_FAIL',
        ip_origen: ip,
        resultado: 'DENEGADO',
        detalle: `estado=${user.estado}`,
      });
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    if (user.origen_autenticacion === 'ENTRA') {
      await logEvent({
        id_cuenta: user.id_cuenta,
        tipo_evento: 'LOGIN_FAIL',
        ip_origen: ip,
        resultado: 'DENEGADO',
        detalle: 'origen_autenticacion=ENTRA',
      });
      return res.status(403).json({ error: 'Este usuario debe autenticarse con Entra ID' });
    }

    if (!user.password_hash) {
      await logEvent({
        id_cuenta: user.id_cuenta,
        tipo_evento: 'LOGIN_FAIL',
        ip_origen: ip,
        resultado: 'ERROR',
        detalle: 'Sin credencial local',
      });
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    if (user.bloqueo_hasta) {
      const bloqueadoHasta = new Date(user.bloqueo_hasta);
      if (bloqueadoHasta.getTime() > Date.now()) {
        await logEvent({
          id_cuenta: user.id_cuenta,
          tipo_evento: 'LOGIN_FAIL',
          ip_origen: ip,
          resultado: 'DENEGADO',
          detalle: `Bloqueado hasta ${bloqueadoHasta.toISOString()}`,
        });
        return res.status(423).json({
          error: 'Cuenta bloqueada temporalmente por intentos fallidos',
          bloqueo_hasta: user.bloqueo_hasta,
        });
      }
    }

    const ok = await bcrypt.compare(password, user.password_hash);

    if (!ok) {
      const fails = Number(user.intentos_fallidos || 0) + 1;
      let bloqueoHasta = null;

      if (fails >= MAX_FAILED) {
        bloqueoHasta = new Date(Date.now() + LOCK_MINUTES * 60 * 1000);
      }

      await pool.execute(
        `UPDATE credencial SET intentos_fallidos = ?, bloqueo_hasta = ? WHERE id_cuenta = ?`,
        [fails, bloqueoHasta, user.id_cuenta]
      );

      await logEvent({
        id_cuenta: user.id_cuenta,
        tipo_evento: 'LOGIN_FAIL',
        ip_origen: ip,
        resultado: 'DENEGADO',
        detalle: `Password incorrecta. intentos=${fails}${bloqueoHasta ? ' (bloqueado)' : ''}`,
      });

      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    await pool.execute(
      `UPDATE credencial SET intentos_fallidos = 0, bloqueo_hasta = NULL WHERE id_cuenta = ?`,
      [user.id_cuenta]
    );

    const token = signToken(user);

    await logEvent({
      id_cuenta: user.id_cuenta,
      tipo_evento: 'LOGIN_OK',
      ip_origen: ip,
      resultado: 'OK',
      detalle: `Login OK role=${user.tipo_cuenta} tenant=${user.id_empresa ?? 'null'}`,
    });

    res.json({
      token,
      user: {
        id: user.id_cuenta,
        email: user.correo,
        role: user.tipo_cuenta,
        requiere_reset: !!user.requiere_reset,
      },
    });
  } catch (e) {
    return dbError(res, e, 'Error en login');
  }
});

/**
 * Registro público SOLO CLIENTE (paciente)
 * y elige empresa EXISTENTE (tenant cerrado).
 */
app.post('/auth/register', async (req, res) => {
  const ip = req.ip;

  const correo = String(req.body?.correo || '').trim().toLowerCase();
  const nombre = String(req.body?.nombre || '').trim();
  const id_empresa = Number(req.body?.id_empresa);
  const password = String(req.body?.password || '');

  if (!correo || !nombre || !id_empresa || !password) {
    return res.status(400).json({ error: 'correo, nombre, id_empresa y password son obligatorios' });
  }

  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo);
  if (!emailOk) return res.status(400).json({ error: 'correo inválido' });

  if (!isStrongPassword(password)) {
    return res.status(400).json({
      error: 'La contraseña debe tener 8+ caracteres, 1 mayúscula, 1 número y 1 carácter especial',
    });
  }

  const tipo_cuenta = 'CLIENTE';

  let conn;
  try {
    conn = await pool.getConnection();
    await conn.beginTransaction();

    // Validar empresa existente y ACTIVA
    const [erows] = await conn.execute(
      `SELECT id_empresa, nombre
       FROM empresa
       WHERE id_empresa = ? AND estado = 'ACTIVA'
       LIMIT 1`,
      [id_empresa]
    );

    if (!erows.length) {
      await conn.rollback();
      return res.status(400).json({ error: 'Empresa inválida o inactiva' });
    }

    const empresaNombre = erows[0].nombre;

    // Crear cuenta
    const [r1] = await conn.execute(
      `INSERT INTO cuenta (correo, nombre, empresa, tipo_cuenta, estado, origen_autenticacion, id_empresa)
       VALUES (?, ?, ?, 'CLIENTE', 'ACTIVA', 'LOCAL', ?)`,
      [correo, nombre, empresaNombre, id_empresa]
    );

    const id_cuenta = r1.insertId;

    // Crear credencial
    const password_hash = await bcrypt.hash(password, 12);

    await conn.execute(
      `INSERT INTO credencial (id_cuenta, password_hash, algoritmo, requiere_reset, intentos_fallidos, bloqueo_hasta, mfa_habilitado)
       VALUES (?, ?, 'bcrypt', 0, 0, NULL, 0)`,
      [id_cuenta, password_hash]
    );

    // Evento (si existe)
    try {
      await conn.execute(
        `INSERT INTO evento_seguridad (id_cuenta, tipo_evento, ip_origen, resultado, detalle)
         VALUES (?, 'REGISTER_OK', ?, 'OK', 'Registro cliente local')`,
        [id_cuenta, ip]
      );
    } catch {}

    await conn.commit();

    // Auto-login
    const token = signToken({ id_cuenta, correo, tipo_cuenta });

    return res.status(201).json({
      token,
      user: { id: id_cuenta, email: correo, role: tipo_cuenta },
    });
  } catch (e) {
    if (conn) {
      try { await conn.rollback(); } catch {}
    }

    if (e?.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Ese correo ya está registrado' });
    }

    console.error(e);
    return res.status(500).json({
      error: 'Error registrando cliente',
      detail: e?.sqlMessage || String(e),
    });
  } finally {
    if (conn) conn.release();
  }
});

// Empresas públicas para desplegable del registro
app.get('/empresas/public', async (_req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id_empresa, nombre
       FROM empresa
       WHERE estado = 'ACTIVA'
       ORDER BY nombre ASC`
    );
    res.json(rows);
  } catch (e) {
    return dbError(res, e, 'Error listando empresas');
  }
});

// Perfil
app.get('/me', auth, async (req, res) => {
  const id = req.user.sub;
  try {
    const [rows] = await pool.execute(
      'SELECT id_cuenta, correo, nombre, tipo_cuenta, estado, id_empresa FROM cuenta WHERE id_cuenta = ? LIMIT 1',
      [id]
    );
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(rows[0]);
  } catch (e) {
    return dbError(res, e, 'Error en /me');
  }
});

/* =========================
   FILES (PACIENTE)
   ========================= */

/**
 * LISTAR ARCHIVOS (propietaria = usuario)
 * - Solo tiene sentido para CLIENTE (paciente)
 */
app.get('/files', auth, async (req, res) => {
  const id = req.user.sub;
  const role = String(req.user.role || '').toUpperCase();
  const ip = req.ip;

  if (role !== 'CLIENTE') {
    return res.status(403).json({ error: 'Solo pacientes pueden listar sus archivos aquí' });
  }

  try {
    const [files] = await pool.execute(
      `SELECT id_archivo, id_cuenta_propietaria, id_cuenta_subidora, nombre_original,
              uri_almacenamiento, hash_sha256, estado_archivo, tamano_bytes, fecha_subida
       FROM archivo
       WHERE id_cuenta_propietaria = ?
       ORDER BY fecha_subida DESC`,
      [id]
    );

    await logEvent({
      id_cuenta: id,
      tipo_evento: 'LISTA_ARCHIVOS',
      ip_origen: ip,
      resultado: 'OK',
      detalle: `role=${role}`,
    });

    res.json(files);
  } catch (e) {
    return dbError(res, e, 'Error listando archivos');
  }
});

/**
 * SUBIR ARCHIVO (PDF)
 * - Solo CLIENTE (paciente)
 */
app.post('/files/upload', auth, (req, res) => {
  const role = String(req.user.role || '').toUpperCase();
  if (role !== 'CLIENTE') return res.status(403).json({ error: 'Solo pacientes pueden subir archivos' });

  upload.single('file')(req, res, async (err) => {
    if (err) return res.status(400).json({ error: 'Upload rejected', detail: String(err.message || err) });
    if (!req.file) return res.status(400).json({ error: 'file required' });

    const id = req.user.sub;
    const ip = req.ip;

    try {
      const filePath = req.file.path;
      const sha256 = await sha256File(filePath);

      const nombre_original = req.file.originalname;
      const tamano_bytes = req.file.size;
      const uri_almacenamiento = `/storage/${req.file.filename}`;

      const [result] = await pool.execute(
        `INSERT INTO archivo
          (id_cuenta_propietaria, id_cuenta_subidora, nombre_original, uri_almacenamiento,
           hash_sha256, estado_archivo, tamano_bytes, fecha_subida)
         VALUES (?, ?, ?, ?, ?, 'ACTIVO', ?, NOW())`,
        [id, id, nombre_original, uri_almacenamiento, sha256, tamano_bytes]
      );

      await logEvent({
        id_cuenta: id,
        id_archivo: result.insertId,
        tipo_evento: 'SUBIDA',
        ip_origen: ip,
        resultado: 'OK',
        detalle: `Upload role=${role} name=${nombre_original}`,
      });

      res.json({
        ok: true,
        id_archivo: result.insertId,
        nombre_original,
        tamano_bytes,
        hash_sha256: sha256,
        estado_archivo: 'ACTIVO',
        uri_almacenamiento,
      });
    } catch (e) {
      return dbError(res, e, 'Upload failed');
    }
  });
});

/**
 * ELIMINAR ARCHIVO (soft delete + borrar físico si está en /storage)
 * - Solo CLIENTE (propietario)
 */
app.delete('/files/:id', auth, async (req, res) => {
  const userId = req.user.sub;
  const role = String(req.user.role || '').toUpperCase();
  const ip = req.ip;
  const idArchivo = Number(req.params.id);

  if (role !== 'CLIENTE') return res.status(403).json({ error: 'Solo pacientes pueden borrar archivos' });
  if (!idArchivo) return res.status(400).json({ error: 'Invalid file id' });

  try {
    const [rows] = await pool.execute(
      `SELECT id_archivo, id_cuenta_propietaria, uri_almacenamiento, estado_archivo
       FROM archivo
       WHERE id_archivo = ?
       LIMIT 1`,
      [idArchivo]
    );

    if (!rows.length) return res.status(404).json({ error: 'File not found' });
    const file = rows[0];

    if (Number(file.id_cuenta_propietaria) !== Number(userId)) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    await pool.execute(`UPDATE archivo SET estado_archivo = 'ELIMINADO' WHERE id_archivo = ?`, [idArchivo]);

    if (file.uri_almacenamiento && file.uri_almacenamiento.startsWith('/storage/')) {
      const filename = path.basename(file.uri_almacenamiento);
      const diskPath = path.join(STORAGE_PATH, filename);
      fs.unlink(diskPath, (err) => {
        if (err) console.log('[DELETE] unlink warning:', err.message);
      });
    }

    await logEvent({
      id_cuenta: userId,
      id_archivo: idArchivo,
      tipo_evento: 'ELIMINA_ARCHIVO',
      ip_origen: ip,
      resultado: 'OK',
      detalle: `Delete role=${role}`,
    });

    res.json({ ok: true });
  } catch (e) {
    return dbError(res, e, 'Delete failed');
  }
});

/* =========================
   PANEL EMPLEADOS HOSPITAL (TENANT)
   =========================
   ✅ cambio pedido (c):
   - Solo empleados del hospital (TRABAJADOR con id_empresa != NULL)
   - Devuelve SOLO archivos de pacientes (CLIENTE) del mismo id_empresa
*/
app.get('/staff/files', auth, async (req, res) => {
  const userId = req.user.sub;
  const role = String(req.user.role || '').toUpperCase();

  if (!isStaffRole(role)) return res.status(403).json({ error: 'Forbidden' });

  const q = String(req.query.q || '').trim().toLowerCase();

  try {
    const u = await getUserCtx(userId);
    if (!u || u.estado !== 'ACTIVA') return res.status(403).json({ error: 'Forbidden' });

    // Solo empleados hospital
    if (!isHospitalWorker(u)) {
      return res.status(403).json({ error: 'Solo empleados del hospital pueden usar este panel' });
    }

    const like = `%${q}%`;

    const [rows] = await pool.execute(
      `
      SELECT
        f.id_archivo,
        f.nombre_original,
        f.uri_almacenamiento,
        f.hash_sha256,
        f.estado_archivo,
        f.tamano_bytes,
        f.fecha_subida,

        p.id_cuenta AS paciente_id,
        p.nombre   AS paciente_nombre,
        p.correo   AS paciente_correo,
        p.id_empresa AS paciente_empresa_id
      FROM archivo f
      JOIN cuenta p ON p.id_cuenta = f.id_cuenta_propietaria
      WHERE
        p.tipo_cuenta = 'CLIENTE'
        AND p.id_empresa = ?
        AND (
          ? = '' OR
          LOWER(p.nombre) LIKE ? OR
          LOWER(p.correo) LIKE ? OR
          LOWER(f.nombre_original) LIKE ?
        )
      ORDER BY f.fecha_subida DESC
      `,
      [u.id_empresa, q, like, like, like]
    );

    res.json(rows);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Error listando archivos del tenant', detail: e?.sqlMessage || String(e) });
  }
});

/* =========================
   CONTACTO (PUBLIC)
   ========================= */
app.post('/contact', contactLimiter, async (req, res) => {
  try {
    const { correo, mensaje } = req.body || {};
    const email = String(correo || '').trim();
    const text = String(mensaje || '').trim();

    if (!email || !text) return res.status(400).json({ error: 'correo y mensaje son obligatorios' });

    const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    if (!emailOk) return res.status(400).json({ error: 'correo inválido' });

    if (text.length < 10) return res.status(400).json({ error: 'El mensaje es demasiado corto' });
    if (text.length > 5000) return res.status(400).json({ error: 'El mensaje es demasiado largo (máx 5000)' });

    if (!mailTransport) {
      return res.status(500).json({
        error: 'Email no configurado en el servidor. Falta SMTP_USER/SMTP_PASS.',
      });
    }

    const id = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
    const to = CONTACT_TO || 'medicloud54@gmail.com';

    const ip = req.ip;
    const ua = req.headers['user-agent'] || '';

    const subject = `MediCloud · Contacto web · ${email} · ${id}`;
    const body = `Nuevo mensaje de contacto (web)

ID: ${id}
Correo: ${email}
IP: ${ip}
User-Agent: ${ua}

Mensaje:
${text}
`;

    await mailTransport.sendMail({
      from: `MediCloud Contacto <${SMTP_USER}>`,
      to,
      replyTo: email,
      subject,
      text: body,
    });

    return res.status(201).json({ ok: true, id });
  } catch (e) {
    console.error('[CONTACT] error:', e);
    return res.status(500).json({ error: 'No se pudo enviar el mensaje' });
  }
});

/* =========================
   TICKETS (SOLO HOSPITAL <-> MEDICLOUD)
   =========================
   ✅ cambio pedido:
   - SOLO TRABAJADOR/ADMIN
   - Hospital (TRABAJADOR con id_empresa): ABRE tickets y escribe mensajes, puede cerrar.
   - MediCloud (TRABAJADOR sin id_empresa + ADMIN): gestionan y responden, asignan, prioridad, estados.
*/

async function getTicketByIdFull(ticketId) {
  const [rows] = await pool.execute(
    `
    SELECT
      t.*,
      c.correo  AS cliente_correo,
      c.id_empresa AS cliente_empresa_id,
      cr.correo AS creador_correo,
      cr.id_empresa AS creador_empresa_id,
      a.correo  AS asignado_correo,
      a.id_empresa AS asignado_empresa_id
    FROM ticket t
    JOIN cuenta c  ON c.id_cuenta  = t.id_cuenta_cliente
    JOIN cuenta cr ON cr.id_cuenta = t.id_cuenta_creador
    LEFT JOIN cuenta a ON a.id_cuenta = t.id_cuenta_asignado
    WHERE t.id_ticket = ?
    LIMIT 1
    `,
    [ticketId]
  );
  return rows[0] || null;
}

function canAccessTicket(ctx, ticket) {
  if (!ctx || !ticket) return false;

  // Admin MediCloud: todo
  if (String(ctx.tipo_cuenta).toUpperCase() === 'ADMIN') return true;

  // MediCloud TRABAJADOR (id_empresa NULL):
  if (isMediCloudWorker(ctx)) {
    // ve los no asignados + los asignados a él + los creados por él
    return (
      ticket.id_cuenta_asignado == null ||
      Number(ticket.id_cuenta_asignado) === Number(ctx.id_cuenta) ||
      Number(ticket.id_cuenta_creador) === Number(ctx.id_cuenta)
    );
  }

  // Hospital TRABAJADOR (tenant):
  if (isHospitalWorker(ctx)) {
    // ve tickets del mismo hospital (tenant) (creados por su hospital)
    return Number(ticket.creador_empresa_id || 0) === Number(ctx.id_empresa);
  }

  return false;
}

app.get('/tickets', auth, async (req, res) => {
  const id = req.user.sub;
  const role = String(req.user.role || '').toUpperCase();
  const ip = req.ip;

  if (!isStaffRole(role)) return res.status(403).json({ error: 'Forbidden' });

  try {
    const ctx = await getUserCtx(id);
    if (!ctx || ctx.estado !== 'ACTIVA') return res.status(403).json({ error: 'Forbidden' });

    let where = '';
    let params = [];

    if (String(ctx.tipo_cuenta).toUpperCase() === 'ADMIN') {
      where = '';
      params = [];
    } else if (isMediCloudWorker(ctx)) {
      // MediCloud TRABAJADOR: lo suyo + no asignados
      where = `WHERE (t.id_cuenta_asignado = ? OR t.id_cuenta_creador = ? OR t.id_cuenta_asignado IS NULL)`;
      params = [id, id];
    } else if (isHospitalWorker(ctx)) {
      // Hospital: tickets de su hospital (tenant)
      where = `WHERE cr.id_empresa = ?`;
      params = [ctx.id_empresa];
    } else {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const [rows] = await pool.execute(
      `
      SELECT
        t.id_ticket, t.id_cuenta_cliente, t.id_cuenta_creador, t.id_cuenta_asignado,
        t.tipo_ticket, t.prioridad, t.estado, t.asunto,
        t.creado_en, t.actualizado_en, t.cerrado_en,
        c.correo AS cliente_correo,
        cr.correo AS creador_correo,
        cr.id_empresa AS creador_empresa_id,
        a.correo AS asignado_correo,
        (SELECT COUNT(*) FROM ticket_mensaje m WHERE m.id_ticket = t.id_ticket) AS mensajes
      FROM ticket t
      JOIN cuenta c  ON c.id_cuenta  = t.id_cuenta_cliente
      JOIN cuenta cr ON cr.id_cuenta = t.id_cuenta_creador
      LEFT JOIN cuenta a ON a.id_cuenta = t.id_cuenta_asignado
      ${where}
      ORDER BY t.actualizado_en DESC, t.creado_en DESC
      `,
      params
    );

    await logEvent({
      id_cuenta: id,
      tipo_evento: 'TICKET_LISTA',
      ip_origen: ip,
      resultado: 'OK',
      detalle: `role=${ctx.tipo_cuenta} tenant=${ctx.id_empresa ?? 'null'}`,
    });

    res.json(rows);
  } catch (e) {
    return dbError(res, e, 'Error listando tickets');
  }
});

app.post('/tickets', auth, async (req, res) => {
  const creadorId = req.user.sub;
  const role = String(req.user.role || '').toUpperCase();
  const ip = req.ip;

  if (!isStaffRole(role)) return res.status(403).json({ error: 'Forbidden' });

  const { asunto, descripcion } = req.body || {};

  if (!asunto || !String(asunto).trim()) return res.status(400).json({ error: 'asunto required' });

  try {
    const ctx = await getUserCtx(creadorId);
    if (!ctx || ctx.estado !== 'ACTIVA') return res.status(403).json({ error: 'Forbidden' });

    // ✅ Hospital staff: SOLO abre tickets hacia MediCloud
    if (isHospitalWorker(ctx)) {
      const prioridadInicial = 'MEDIA';

      const [r] = await pool.execute(
        `
        INSERT INTO ticket
        (id_cuenta_cliente, id_cuenta_creador, id_cuenta_asignado, tipo_ticket, prioridad, estado, asunto, descripcion_inicial, creado_en, actualizado_en)
        VALUES (?, ?, NULL, 'HOSPITAL_A_MEDICLOUD', ?, 'ABIERTO', ?, ?, NOW(), NOW())
        `,
        [creadorId, creadorId, prioridadInicial, String(asunto).trim(), descripcion ? String(descripcion).trim() : null]
      );

      const ticketId = r.insertId;

      if (descripcion && String(descripcion).trim()) {
        await pool.execute(
          `INSERT INTO ticket_mensaje (id_ticket, id_cuenta_autor, cuerpo) VALUES (?, ?, ?)`,
          [ticketId, creadorId, String(descripcion).trim()]
        );
        await pool.execute(`UPDATE ticket SET actualizado_en = NOW() WHERE id_ticket = ?`, [ticketId]);
      }

      await logEvent({
        id_cuenta: creadorId,
        tipo_evento: 'TICKET_CREADO',
        ip_origen: ip,
        resultado: 'OK',
        detalle: `ticket=${ticketId} tipo=HOSPITAL_A_MEDICLOUD`,
      });

      return res.status(201).json({ ok: true, id_ticket: ticketId });
    }

    // ✅ MediCloud staff/admin: opcionalmente puede abrir tickets (si lo necesitas en tu flujo)
    if (isMediCloudWorker(ctx) || String(ctx.tipo_cuenta).toUpperCase() === 'ADMIN') {
      // Por seguridad, si quieres bloquear creación desde MediCloud, cambia a 403 aquí.
      const prioridadInicial = 'MEDIA';

      const [r] = await pool.execute(
        `
        INSERT INTO ticket
        (id_cuenta_cliente, id_cuenta_creador, id_cuenta_asignado, tipo_ticket, prioridad, estado, asunto, descripcion_inicial, creado_en, actualizado_en)
        VALUES (?, ?, NULL, 'MEDICLOUD_A_HOSPITAL', ?, 'ABIERTO', ?, ?, NOW(), NOW())
        `,
        [creadorId, creadorId, prioridadInicial, String(asunto).trim(), descripcion ? String(descripcion).trim() : null]
      );

      const ticketId = r.insertId;

      if (descripcion && String(descripcion).trim()) {
        await pool.execute(
          `INSERT INTO ticket_mensaje (id_ticket, id_cuenta_autor, cuerpo) VALUES (?, ?, ?)`,
          [ticketId, creadorId, String(descripcion).trim()]
        );
        await pool.execute(`UPDATE ticket SET actualizado_en = NOW() WHERE id_ticket = ?`, [ticketId]);
      }

      await logEvent({
        id_cuenta: creadorId,
        tipo_evento: 'TICKET_CREADO',
        ip_origen: ip,
        resultado: 'OK',
        detalle: `ticket=${ticketId} tipo=MEDICLOUD_A_HOSPITAL`,
      });

      return res.status(201).json({ ok: true, id_ticket: ticketId });
    }

    return res.status(403).json({ error: 'Forbidden' });
  } catch (e) {
    return dbError(res, e, 'Error creando ticket');
  }
});

app.get('/tickets/:id', auth, async (req, res) => {
  const userId = req.user.sub;
  const role = String(req.user.role || '').toUpperCase();
  const ip = req.ip;

  if (!isStaffRole(role)) return res.status(403).json({ error: 'Forbidden' });

  const ticketId = Number(req.params.id);
  if (!ticketId) return res.status(400).json({ error: 'Invalid ticket id' });

  try {
    const ctx = await getUserCtx(userId);
    if (!ctx || ctx.estado !== 'ACTIVA') return res.status(403).json({ error: 'Forbidden' });

    const ticket = await getTicketByIdFull(ticketId);
    if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

    if (!canAccessTicket(ctx, ticket)) return res.status(403).json({ error: 'Forbidden' });

    const [mrows] = await pool.execute(
      `
      SELECT
        m.id_mensaje, m.id_ticket, m.id_cuenta_autor, m.cuerpo,
        m.enviado_en,
        a.correo AS autor_correo,
        a.tipo_cuenta AS autor_tipo
      FROM ticket_mensaje m
      JOIN cuenta a ON a.id_cuenta = m.id_cuenta_autor
      WHERE m.id_ticket = ?
      ORDER BY m.enviado_en ASC
      `,
      [ticketId]
    );

    let adjuntos = [];
    try {
      const [arows] = await pool.execute(
        `
        SELECT
          ta.id_ticket_archivo, ta.creado_en,
          f.id_archivo, f.nombre_original, f.uri_almacenamiento, f.hash_sha256, f.estado_archivo, f.tamano_bytes, f.fecha_subida
        FROM ticket_archivo ta
        JOIN archivo f ON f.id_archivo = ta.id_archivo
        WHERE ta.id_ticket = ?
        ORDER BY ta.creado_en DESC
        `,
        [ticketId]
      );
      adjuntos = arows;
    } catch (e) {
      console.warn('[ticket adjuntos] warn:', e.code, e.sqlMessage);
      adjuntos = [];
    }

    await logEvent({
      id_cuenta: userId,
      tipo_evento: 'TICKET_VER',
      ip_origen: ip,
      resultado: 'OK',
      detalle: `ticket=${ticketId} role=${ctx.tipo_cuenta}`,
    });

    res.json({ ticket, mensajes: mrows, adjuntos });
  } catch (e) {
    return dbError(res, e, 'Error leyendo ticket');
  }
});

async function handleAddTicketMessage(req, res) {
  const userId = req.user.sub;
  const role = String(req.user.role || '').toUpperCase();
  const ip = req.ip;

  if (!isStaffRole(role)) return res.status(403).json({ error: 'Forbidden' });

  const ticketId = Number(req.params.id);
  const { cuerpo } = req.body || {};

  if (!ticketId) return res.status(400).json({ error: 'Invalid ticket id' });
  if (!cuerpo || !String(cuerpo).trim()) return res.status(400).json({ error: 'cuerpo required' });

  try {
    const ctx = await getUserCtx(userId);
    if (!ctx || ctx.estado !== 'ACTIVA') return res.status(403).json({ error: 'Forbidden' });

    const ticket = await getTicketByIdFull(ticketId);
    if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

    if (!canAccessTicket(ctx, ticket)) return res.status(403).json({ error: 'Forbidden' });

    await pool.execute(
      `INSERT INTO ticket_mensaje (id_ticket, id_cuenta_autor, cuerpo) VALUES (?, ?, ?)`,
      [ticketId, userId, String(cuerpo).trim()]
    );

    // ✅ solo si responde MediCloud y ticket estaba ABIERTO => EN_PROCESO
    if (isMediCloudWorker(ctx) && String(ticket.estado).toUpperCase() === 'ABIERTO') {
      await pool.execute(
        `UPDATE ticket SET estado = 'EN_PROCESO', actualizado_en = NOW() WHERE id_ticket = ?`,
        [ticketId]
      );
    } else {
      await pool.execute(`UPDATE ticket SET actualizado_en = NOW() WHERE id_ticket = ?`, [ticketId]);
    }

    await logEvent({
      id_cuenta: userId,
      tipo_evento: 'TICKET_MSG',
      ip_origen: ip,
      resultado: 'OK',
      detalle: `ticket=${ticketId} role=${ctx.tipo_cuenta}`,
    });

    res.status(201).json({ ok: true });
  } catch (e) {
    return dbError(res, e, 'Error enviando mensaje');
  }
}

app.post('/tickets/:id/messages', auth, handleAddTicketMessage);
app.post('/tickets/:id/mensajes', auth, handleAddTicketMessage);

/**
 * PATCH /tickets/:id
 * - Hospital worker: SOLO puede cerrar su ticket (estado=CERRADO). No asigna, no prioridad, no estados internos.
 * - MediCloud worker/admin: puede asignar, estados, prioridad.
 */
app.patch('/tickets/:id', auth, async (req, res) => {
  const userId = req.user.sub;
  const role = String(req.user.role || '').toUpperCase();
  const ip = req.ip;

  if (!isStaffRole(role)) return res.status(403).json({ error: 'Forbidden' });

  const ticketId = Number(req.params.id);
  if (!ticketId) return res.status(400).json({ error: 'Invalid ticket id' });

  const { estado = null, asignar_a_mi = false, id_cuenta_asignado = null, prioridad = null } = req.body || {};

  try {
    const ctx = await getUserCtx(userId);
    if (!ctx || ctx.estado !== 'ACTIVA') return res.status(403).json({ error: 'Forbidden' });

    const ticket = await getTicketByIdFull(ticketId);
    if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

    if (!canAccessTicket(ctx, ticket)) return res.status(403).json({ error: 'Forbidden' });

    const newEstado = estado ? normalizeEstado(estado) : null;
    const newPrioridad = prioridad ? normalizePrioridad(prioridad) : null;

    // Hospital staff: solo cerrar
    if (isHospitalWorker(ctx)) {
      if (newPrioridad) return res.status(403).json({ error: 'Hospital no puede modificar prioridad' });
      if (asignar_a_mi || id_cuenta_asignado) return res.status(403).json({ error: 'Hospital no puede asignar tickets' });
      if (newEstado && newEstado !== 'CERRADO') {
        return res.status(403).json({ error: 'Hospital solo puede cerrar el ticket' });
      }
    }

    // Prioridad: solo MediCloud staff/admin
    if (newPrioridad && !(isMediCloudWorker(ctx) || String(ctx.tipo_cuenta).toUpperCase() === 'ADMIN')) {
      return res.status(403).json({ error: 'No autorizado a cambiar prioridad' });
    }
    if (newPrioridad) {
      const allowed = new Set(['BAJA', 'MEDIA', 'ALTA']);
      if (!allowed.has(newPrioridad)) return res.status(400).json({ error: 'prioridad inválida' });
    }

    // Asignación: solo MediCloud staff/admin
    let asignado = ticket.id_cuenta_asignado;
    if ((isMediCloudWorker(ctx) || String(ctx.tipo_cuenta).toUpperCase() === 'ADMIN') && asignar_a_mi) {
      asignado = userId;
    }
    if (String(ctx.tipo_cuenta).toUpperCase() === 'ADMIN' && id_cuenta_asignado) {
      asignado = Number(id_cuenta_asignado);
    }

    let estadoFinal = newEstado || String(ticket.estado).toUpperCase();

    let cerradoEn = ticket.cerrado_en;
    if (estadoFinal === 'CERRADO' || estadoFinal === 'RESUELTO') {
      cerradoEn = cerradoEn || new Date();
    } else {
      cerradoEn = null;
    }

    const sets = [];
    const params = [];

    sets.push('estado = ?'); params.push(estadoFinal);
    sets.push('id_cuenta_asignado = ?'); params.push(asignado || null);
    sets.push('cerrado_en = ?'); params.push(cerradoEn ? new Date(cerradoEn) : null);

    if (newPrioridad && (isMediCloudWorker(ctx) || String(ctx.tipo_cuenta).toUpperCase() === 'ADMIN')) {
      sets.push('prioridad = ?'); params.push(newPrioridad);
    }

    sets.push('actualizado_en = NOW()');
    params.push(ticketId);

    await pool.execute(`UPDATE ticket SET ${sets.join(', ')} WHERE id_ticket = ?`, params);

    await logEvent({
      id_cuenta: userId,
      tipo_evento: 'TICKET_UPDATE',
      ip_origen: ip,
      resultado: 'OK',
      detalle: `ticket=${ticketId} estado=${estadoFinal} asignado=${asignado || 'null'}${newPrioridad ? ` prioridad=${newPrioridad}` : ''}`,
    });

    res.json({ ok: true });
  } catch (e) {
    return dbError(res, e, 'Error actualizando ticket');
  }
});

/* =========================
   ADMIN (MediCloud Management)
   - Solo ADMIN
   ========================= */

// GET /admin/empresas -> lista empresas (ACTIVA/INACTIVA)
app.get('/admin/empresas', auth, requireAdmin, async (_req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id_empresa, nombre, estado, creado_en
       FROM empresa
       ORDER BY nombre ASC`
    );
    res.json(rows);
  } catch (e) {
    return dbError(res, e, 'Error listando empresas (admin)');
  }
});

// GET /admin/empresas/:id/trabajadores -> trabajadores del hospital (por tenant)
app.get('/admin/empresas/:id/trabajadores', auth, requireAdmin, async (req, res) => {
  const id_empresa = Number(req.params.id);
  if (!id_empresa) return res.status(400).json({ error: 'id_empresa inválido' });

  try {
    // (opcional) verifica que la empresa existe
    const [e] = await pool.execute(
      `SELECT id_empresa FROM empresa WHERE id_empresa = ? LIMIT 1`,
      [id_empresa]
    );
    if (!e.length) return res.status(404).json({ error: 'Empresa no encontrada' });

    const [rows] = await pool.execute(
      `SELECT
         id_cuenta, correo, nombre, estado, origen_autenticacion, id_empresa, creado_en
       FROM cuenta
       WHERE tipo_cuenta = 'TRABAJADOR'
         AND id_empresa = ?
       ORDER BY nombre ASC, correo ASC`,
      [id_empresa]
    );

    res.json(rows);
  } catch (e) {
    return dbError(res, e, 'Error listando trabajadores (admin)');
  }
});

// (Opcional) POST /admin/empresas -> crear empresa
app.post('/admin/empresas', auth, requireAdmin, async (req, res) => {
  const nombre = String(req.body?.nombre || '').trim();
  if (!nombre) return res.status(400).json({ error: 'nombre es obligatorio' });

  try {
    const [r] = await pool.execute(
      `INSERT INTO empresa (nombre, estado) VALUES (?, 'ACTIVA')`,
      [nombre]
    );
    res.status(201).json({ ok: true, id_empresa: r.insertId });
  } catch (e) {
    if (e?.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Ya existe una empresa con ese nombre' });
    }
    return dbError(res, e, 'Error creando empresa (admin)');
  }
});

// (Opcional) PATCH /admin/empresas/:id -> activar/desactivar (y opcional renombrar)
app.patch('/admin/empresas/:id', auth, requireAdmin, async (req, res) => {
  const id_empresa = Number(req.params.id);
  if (!id_empresa) return res.status(400).json({ error: 'id_empresa inválido' });

  const estado = req.body?.estado ? String(req.body.estado).trim().toUpperCase() : null;
  const nombre = req.body?.nombre ? String(req.body.nombre).trim() : null;

  if (!estado && !nombre) {
    return res.status(400).json({ error: 'Debes enviar estado y/o nombre' });
  }
  if (estado && !['ACTIVA', 'INACTIVA'].includes(estado)) {
    return res.status(400).json({ error: 'estado inválido (ACTIVA/INACTIVA)' });
  }

  try {
    const sets = [];
    const params = [];

    if (nombre) { sets.push('nombre = ?'); params.push(nombre); }
    if (estado) { sets.push('estado = ?'); params.push(estado); }

    params.push(id_empresa);

    const [r] = await pool.execute(
      `UPDATE empresa SET ${sets.join(', ')} WHERE id_empresa = ?`,
      params
    );

    if (r.affectedRows === 0) return res.status(404).json({ error: 'Empresa no encontrada' });

    res.json({ ok: true });
  } catch (e) {
    if (e?.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Ya existe una empresa con ese nombre' });
    }
    return dbError(res, e, 'Error actualizando empresa (admin)');
  }
});

/* =========================
   EVENTOS GENÉRICOS
   ========================= */
app.post('/events', auth, async (req, res) => {
  const id = req.user.sub;
  const ip = req.ip;
  const { tipo_evento, resultado, detalle, id_archivo = null, id_factura = null } = req.body || {};

  if (!tipo_evento) return res.status(400).json({ error: 'tipo_evento required' });

  try {
    await pool.execute(
      `INSERT INTO evento_seguridad (id_cuenta, id_archivo, id_factura, tipo_evento, ip_origen, resultado, detalle)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [id, id_archivo, id_factura, tipo_evento, ip, resultado || null, detalle || null]
    );
    res.json({ ok: true });
  } catch (e) {
    return dbError(res, e, 'Error registrando evento');
  }
});

app.get('/', (_req, res) => {
  res.type('text').send('MediCloud API OK. Usa /health, /auth/login, /me, /files, /files/upload, /staff/files, /tickets');
});

app.listen(PORT, () => console.log(`MediCloud API running on http://localhost:${PORT}`));
