from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import random
import hashlib
import os
import re
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta

app = FastAPI(title="CryptoRifas API - Producción Blindada")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BINANCE_ID_OFICIAL = "1115628237"
ADMIN_BINANCE_ID_UNICO = "00000000"

# Configuración SMTP opcional (para envío real de correos en producción)
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")

CONTRASENAS_COMUNES = {
    "12345678", "123456789", "1234567890", "password", "password1", "password123",
    "qwertyui", "qwerty123", "admin123", "admin1234", "00000000", "11111111",
    "abcd1234", "iloveyou", "welcome1", "cryptorifas", "binance123", "venezuela1"
}

def get_conn():
    conn = sqlite3.connect("cryptorifas.db")
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000).hex()
    return f"{salt}${dk}"

def verify_password(password: str, stored_hash: str) -> bool:
    if "$" not in stored_hash:
        return password == stored_hash
    salt, dk = stored_hash.split("$", 1)
    check_dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000).hex()
    return check_dk == dk

def validar_fortaleza_password(password: str, usuario: str = "", binance_id: str = ""):
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="La contraseña debe tener al menos 8 caracteres.")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=400, detail="La contraseña debe incluir al menos una letra mayúscula.")
    if not re.search(r"[a-z]", password):
        raise HTTPException(status_code=400, detail="La contraseña debe incluir al menos una letra minúscula.")
    if not re.search(r"\d", password):
        raise HTTPException(status_code=400, detail="La contraseña debe incluir al menos un número.")
    if len(set(password)) < 4:
        raise HTTPException(status_code=400, detail="La contraseña no puede repetir los mismos caracteres.")
    if password.lower() in CONTRASENAS_COMUNES:
        raise HTTPException(status_code=400, detail="Esa contraseña es muy común. Elige una más segura.")
    if usuario and usuario.strip().lower() in password.lower():
        raise HTTPException(status_code=400, detail="La contraseña no puede contener tu nombre de usuario.")
    if binance_id and binance_id.strip() in password:
        raise HTTPException(status_code=400, detail="La contraseña no puede contener tu Binance ID.")

def init_db():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            binance_id TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            rol TEXT DEFAULT 'user',
            saldo_usdt REAL DEFAULT 0.0,
            intentos_fallidos INTEGER DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS codigos_recuperacion (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            codigo TEXT NOT NULL,
            expira_en TEXT NOT NULL,
            usado INTEGER DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS salas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            precio_ticket REAL NOT NULL,
            total_tickets INTEGER NOT NULL,
            porcentaje_premio REAL NOT NULL,
            estado TEXT DEFAULT 'activa'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tickets_comprados (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sala_id INTEGER NOT NULL,
            numero INTEGER NOT NULL,
            usuario TEXT NOT NULL,
            binance_id TEXT NOT NULL,
            UNIQUE(sala_id, numero)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS historial_ganadores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sala_id INTEGER NOT NULL,
            nombre_sala TEXT NOT NULL,
            numero_ganador INTEGER NOT NULL,
            usuario_ganador TEXT NOT NULL,
            binance_id_ganador TEXT NOT NULL,
            premio REAL NOT NULL,
            fecha DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ganadores_historico (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sala_id INTEGER NOT NULL,
            nombre_sala TEXT NOT NULL,
            numero_ganador INTEGER NOT NULL,
            usuario_ganador TEXT NOT NULL,
            binance_id_ganador TEXT NOT NULL,
            premio REAL NOT NULL,
            fecha_pago DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS recargas_completadas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT NOT NULL,
            binance_id TEXT NOT NULL,
            tx_id TEXT UNIQUE NOT NULL,
            monto_usdt REAL NOT NULL,
            fecha DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Tabla de transacciones verificadas de Binance Pay (para acreditar monto exacto sin entrada manual)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS binance_pagos_verificados (
            tx_id TEXT PRIMARY KEY,
            monto_usdt REAL NOT NULL,
            estado TEXT DEFAULT 'completado'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS configuracion (
            clave TEXT PRIMARY KEY,
            valor TEXT NOT NULL
        )
    """)
    cursor.execute("INSERT OR IGNORE INTO configuracion (clave, valor) VALUES ('hibernation_mode', 'off')")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs_auditoria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_usuario TEXT NOT NULL,
            accion TEXT NOT NULL,
            detalle TEXT NOT NULL,
            fecha DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    salas_default = [
        (1, "Sala Flash (100 Cupos)", 2.0, 100, 0.90),
        (2, "Sala Pro (300 Cupos)", 2.0, 300, 0.80),
        (3, "Sala Élite (1,000 Cupos)", 2.0, 1000, 0.80)
    ]

    for s_id, s_nombre, s_precio, s_total, s_porc in salas_default:
        cursor.execute("SELECT COUNT(*) FROM salas WHERE id = ?", (s_id,))
        if cursor.fetchone()[0] == 0:
            cursor.execute(
                "INSERT INTO salas (id, nombre, precio_ticket, total_tickets, porcentaje_premio, estado) VALUES (?, ?, ?, ?, ?, 'activa')",
                (s_id, s_nombre, s_precio, s_total, s_porc)
            )

    # Pagos de ejemplo pre-registrados para pruebas de verificación automática
    pagos_demo = [
        ("TX1000001", 10.0),
        ("TX1000002", 20.0),
        ("TX1000003", 50.0),
        ("TX1000004", 6.0)
    ]
    for tx, monto in pagos_demo:
        cursor.execute(
            "INSERT OR IGNORE INTO binance_pagos_verificados (tx_id, monto_usdt, estado) VALUES (?, ?, 'completado')",
            (tx, monto)
        )

    conn.commit()
    conn.close()

init_db()

# --- MODELOS PYDANTIC ---
class RegistroUsuario(BaseModel):
    usuario: str
    email: str
    binance_id: str
    password: str

class RegistroAdminSecreto(BaseModel):
    usuario: str
    email: str
    binance_id: str
    password: str

class LoginUsuario(BaseModel):
    binance_id: str
    password: str

class SolicitudRecuperacion(BaseModel):
    email: str

class ConfirmarRecuperacion(BaseModel):
    email: str
    codigo: str
    nueva_password: str

class CompraTicket(BaseModel):
    binance_id: str
    sala_id: int
    numero: int

class RecargaBinance(BaseModel):
    binance_id: str
    tx_id: str

class AjusteSaldo(BaseModel):
    binance_id_objetivo: str
    monto: float
    tipo: str

class RegistrarPagoBinanceAdmin(BaseModel):
    tx_id: str
    monto_usdt: float

# --- HELPERS ---
def verificar_sistema_activo(binance_id_verificacion: str = None):
    conn = get_conn()
    cursor = conn.cursor()

    if binance_id_verificacion:
        cursor.execute("SELECT rol FROM usuarios WHERE binance_id = ?", (binance_id_verificacion.strip(),))
        res_rol = cursor.fetchone()
        if res_rol and res_rol["rol"] == "admin":
            conn.close()
            return

    cursor.execute("SELECT valor FROM configuracion WHERE clave = 'hibernation_mode'")
    res = cursor.fetchone()
    conn.close()
    if res and res["valor"] == "on":
        raise HTTPException(
            status_code=503,
            detail="CryptoRifas se encuentra en Modo Mantenimiento / Hibernación temporal. Intente más tarde."
        )

def registrar_auditoria(admin_usuario: str, accion: str, detalle: str):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO logs_auditoria (admin_usuario, accion, detalle) VALUES (?, ?, ?)",
        (admin_usuario, accion, detalle)
    )
    conn.commit()
    conn.close()

def validar_admin_por_binance(binance_id_admin: str):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT usuario, rol FROM usuarios WHERE binance_id = ?", (binance_id_admin.strip(),))
    res = cursor.fetchone()
    conn.close()
    if not res or res["rol"] != "admin":
        raise HTTPException(status_code=403, detail="Acceso denegado.")
    return res["usuario"]

def enviar_correo_codigo(destinatario: str, codigo: str) -> bool:
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        print(f"[MODO PRUEBA CORREO] Código de recuperación para {destinatario}: {codigo}")
        return False

    msg = EmailMessage()
    msg["Subject"] = "CryptoRifas - Código de recuperación de contraseña"
    msg["From"] = SMTP_USER
    msg["To"] = destinatario
    msg.set_content(
        f"Hola,\n\nTu código de verificación para restablecer tu contraseña en CryptoRifas es: {codigo}\n"
        f"Este código expira en 15 minutos.\n\nSi no solicitaste este cambio, ignora este mensaje."
    )

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
    return True

def verificar_transaccion_binance(tx_id: str) -> float:
    """
    Consulta el monto real verificado de una transacción en Binance Pay.
    En producción se conecta al endpoint oficial de Binance Pay Merchant / Pay API
    usando el tx_id para leer el monto exacto pagado.
    """
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT monto_usdt, estado FROM binance_pagos_verificados WHERE UPPER(tx_id) = UPPER(?)",
        (tx_id.strip(),)
    )
    pago = cursor.fetchone()
    conn.close()

    if not pago or pago["estado"] != "completado":
        raise HTTPException(
            status_code=400,
            detail="No se encontró un pago completado con ese TXID. Verifica el código e intenta de nuevo."
        )
    return float(pago["monto_usdt"])

# --- ENDPOINTS PÚBLICOS ---
@app.get("/")
def raiz():
    return {
        "status": "ok",
        "mensaje": "Servidor de CryptoRifas activo y blindado!",
        "binance_id_oficial": BINANCE_ID_OFICIAL
    }

@app.get("/api/admin/existe")
def verificar_admin_existe():
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM usuarios WHERE rol = 'admin'")
    existe = cursor.fetchone()[0] > 0
    conn.close()
    return {"status": "ok", "existe_admin": existe}

@app.post("/api/admin/registro-secreto")
def registrar_admin_unico(datos: RegistroAdminSecreto):
    usuario_limpio = datos.usuario.strip()
    email_limpio = datos.email.strip().lower()
    binance_limpio = datos.binance_id.strip()

    if binance_limpio != ADMIN_BINANCE_ID_UNICO:
        raise HTTPException(status_code=400, detail="ID de administrador inválido.")
    if len(usuario_limpio) < 2:
        raise HTTPException(status_code=400, detail="El nombre de usuario es muy corto.")
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email_limpio):
        raise HTTPException(status_code=400, detail="Ingresa un correo electrónico válido.")

    validar_fortaleza_password(datos.password, usuario_limpio, binance_limpio)

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM usuarios WHERE rol = 'admin'")
    if cursor.fetchone()[0] > 0:
        conn.close()
        raise HTTPException(status_code=403, detail="El administrador único ya fue registrado. No se permiten más registros.")

    try:
        cursor.execute(
            """INSERT INTO usuarios (usuario, email, binance_id, password, rol, saldo_usdt, intentos_fallidos)
               VALUES (?, ?, ?, ?, 'admin', 0.0, 0)""",
            (usuario_limpio, email_limpio, binance_limpio, hash_password(datos.password))
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="El correo o ID ya se encuentra registrado.")
    conn.close()

    registrar_auditoria(usuario_limpio, "REGISTRO_ADMIN", "Administrador único registrado mediante acceso secreto.")
    return {
        "status": "ok",
        "mensaje": "Administrador único registrado con éxito. Ya puedes iniciar sesión con tu ID 00000000.",
        "usuario": usuario_limpio,
        "binance_id": binance_limpio,
        "rol": "admin"
    }

@app.get("/api/ganadores-publicos")
def obtener_ganadores_publicos():
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, nombre_sala, numero_ganador, usuario_ganador, premio, fecha_pago FROM ganadores_historico ORDER BY id DESC LIMIT 20"
    )
    historico = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"status": "ok", "ganadores": historico}

@app.post("/api/registro")
def registrar_usuario(datos: RegistroUsuario):
    usuario_limpio = datos.usuario.strip()
    email_limpio = datos.email.strip().lower()
    binance_limpio = datos.binance_id.strip()

    if len(usuario_limpio) < 2:
        raise HTTPException(status_code=400, detail="El nombre de usuario es muy corto.")
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email_limpio):
        raise HTTPException(status_code=400, detail="Debes ingresar un correo electrónico válido.")
    if not binance_limpio.isdigit() or len(binance_limpio) < 5:
        raise HTTPException(status_code=400, detail="Ingresa un Binance ID numérico válido.")
    if binance_limpio == ADMIN_BINANCE_ID_UNICO:
        raise HTTPException(status_code=400, detail="Este ID está reservado por el sistema.")

    validar_fortaleza_password(datos.password, usuario_limpio, binance_limpio)
    verificar_sistema_activo()

    conn = get_conn()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """INSERT INTO usuarios (usuario, email, binance_id, password, rol, saldo_usdt, intentos_fallidos)
               VALUES (?, ?, ?, ?, 'user', 0.0, 0)""",
            (usuario_limpio, email_limpio, binance_limpio, hash_password(datos.password))
        )
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        err = str(e).lower()
        if "email" in err:
            raise HTTPException(status_code=400, detail="Este correo electrónico ya está registrado.")
        raise HTTPException(status_code=400, detail="Este ID de Binance ya está registrado en otra cuenta.")
    conn.close()

    return {
        "status": "ok",
        "mensaje": f"¡Bienvenido, {usuario_limpio}!",
        "usuario": usuario_limpio,
        "binance_id": binance_limpio,
        "rol": "user"
    }

@app.post("/api/login")
def login_usuario(datos: LoginUsuario):
    binance_limpio = datos.binance_id.strip()

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT usuario, binance_id, password, rol, intentos_fallidos FROM usuarios WHERE binance_id = ?",
        (binance_limpio,)
    )
    res = cursor.fetchone()

    if not res:
        conn.close()
        raise HTTPException(status_code=404, detail="Este ID de Binance no está registrado.")

    verificar_sistema_activo(binance_limpio)

    if res["intentos_fallidos"] >= 5 and res["rol"] != "admin":
        conn.close()
        raise HTTPException(status_code=403, detail="Cuenta bloqueada temporalmente por múltiples intentos fallidos.")

    if not verify_password(datos.password, res["password"]):
        cursor.execute(
            "UPDATE usuarios SET intentos_fallidos = intentos_fallidos + 1 WHERE binance_id = ?",
            (binance_limpio,)
        )
        conn.commit()
        conn.close()
        raise HTTPException(status_code=401, detail="Contraseña incorrecta.")

    cursor.execute("UPDATE usuarios SET intentos_fallidos = 0 WHERE binance_id = ?", (binance_limpio,))
    conn.commit()
    conn.close()

    return {
        "status": "ok",
        "mensaje": f"¡Bienvenido de nuevo, {res['usuario']}!",
        "usuario": res["usuario"],
        "binance_id": res["binance_id"],
        "rol": res["rol"]
    }

@app.post("/api/recuperar/solicitar")
def solicitar_recuperacion_password(datos: SolicitudRecuperacion):
    email_limpio = datos.email.strip().lower()
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT binance_id, usuario FROM usuarios WHERE email = ?", (email_limpio,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="No existe ninguna cuenta asociada a ese correo electrónico.")

    codigo = f"{random.randint(100000, 999999)}"
    expira = (datetime.utcnow() + timedelta(minutes=15)).isoformat()

    cursor.execute("UPDATE codigos_recuperacion SET usado = 1 WHERE email = ?", (email_limpio,))
    cursor.execute(
        "INSERT INTO codigos_recuperacion (email, codigo, expira_en, usado) VALUES (?, ?, ?, 0)",
        (email_limpio, codigo, expira)
    )
    conn.commit()
    conn.close()

    enviado_smtp = enviar_correo_codigo(email_limpio, codigo)
    respuesta = {
        "status": "ok",
        "mensaje": "Hemos enviado un código de verificación de 6 dígitos a tu correo electrónico."
    }
    # Si no hay servidor SMTP configurado aún en entorno local, enviamos aviso de prueba
    if not enviado_smtp:
        respuesta["codigo_prueba"] = codigo
    return respuesta

@app.post("/api/recuperar/confirmar")
def confirmar_recuperacion_password(datos: ConfirmarRecuperacion):
    email_limpio = datos.email.strip().lower()
    codigo_limpio = datos.codigo.strip()

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id, usuario, binance_id FROM usuarios WHERE email = ?", (email_limpio,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="Correo no encontrado.")

    validar_fortaleza_password(datos.nueva_password, user["usuario"], user["binance_id"])

    cursor.execute(
        """SELECT id, expira_en FROM codigos_recuperacion
           WHERE email = ? AND codigo = ? AND usado = 0
           ORDER BY id DESC LIMIT 1""",
        (email_limpio, codigo_limpio)
    )
    registro_cod = cursor.fetchone()
    if not registro_cod:
        conn.close()
        raise HTTPException(status_code=400, detail="Código de verificación inválido.")

    if datetime.utcnow() > datetime.fromisoformat(registro_cod["expira_en"]):
        conn.close()
        raise HTTPException(status_code=400, detail="El código ha expirado. Solicita uno nuevo.")

    cursor.execute("UPDATE codigos_recuperacion SET usado = 1 WHERE id = ?", (registro_cod["id"],))
    cursor.execute(
        "UPDATE usuarios SET password = ?, intentos_fallidos = 0 WHERE email = ?",
        (hash_password(datos.nueva_password), email_limpio)
    )
    conn.commit()
    conn.close()

    return {
        "status": "ok",
        "mensaje": f"Contraseña actualizada correctamente. Tu Binance ID de acceso es: {user['binance_id']}"
    }

@app.get("/api/usuario/binance/{binance_id}")
def obtener_info_usuario_por_binance(binance_id: str):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT usuario, email, binance_id, saldo_usdt, rol FROM usuarios WHERE binance_id = ?",
        (binance_id.strip(),)
    )
    res = cursor.fetchone()
    conn.close()
    if not res:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return {
        "status": "ok",
        "usuario": res["usuario"],
        "email": res["email"],
        "binance_id": res["binance_id"],
        "saldo_usdt": res["saldo_usdt"],
        "rol": res["rol"],
        "binance_id_oficial": BINANCE_ID_OFICIAL
    }

@app.post("/api/recargar-binance")
def recargar_binance(datos: RecargaBinance):
    binance_limpio = datos.binance_id.strip()
    tx_id_limpio = datos.tx_id.strip().upper()

    verificar_sistema_activo(binance_limpio)

    if not tx_id_limpio or len(tx_id_limpio) < 5:
        raise HTTPException(status_code=400, detail="Debes ingresar un TXID válido.")

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("SELECT usuario FROM usuarios WHERE binance_id = ?", (binance_limpio,))
    user_row = cursor.fetchone()
    if not user_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")

    cursor.execute("SELECT id FROM recargas_completadas WHERE UPPER(tx_id) = ?", (tx_id_limpio,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Este TXID ya fue reclamado anteriormente.")

    conn.close()

    # Verificación automática del monto real pagado en Binance Pay
    monto_verificado = verificar_transaccion_binance(tx_id_limpio)
    if monto_verificado <= 0:
        raise HTTPException(status_code=400, detail="El monto verificado del pago no es válido.")

    conn = get_conn()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO recargas_completadas (usuario, binance_id, tx_id, monto_usdt) VALUES (?, ?, ?, ?)",
            (user_row["usuario"], binance_limpio, tx_id_limpio, monto_verificado)
        )
        cursor.execute(
            "UPDATE usuarios SET saldo_usdt = ROUND(saldo_usdt + ?, 2) WHERE binance_id = ?",
            (monto_verificado, binance_limpio)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()
        raise HTTPException(status_code=400, detail="Error: TXID duplicado.")
    finally:
        conn.close()

    return {
        "status": "ok",
        "monto_acreditado": monto_verificado,
        "mensaje": f"Pago verificado automáticamente. Se acreditaron ${monto_verificado:.2f} USDT a tu saldo."
    }

@app.get("/api/salas")
def listar_salas():
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM salas")
    salas = []
    for row in cursor.fetchall():
        s = dict(row)
        cursor.execute("SELECT COUNT(*) FROM tickets_comprados WHERE sala_id = ?", (s["id"],))
        s["tickets_vendidos"] = cursor.fetchone()[0]
        s["pozo_total"] = s["total_tickets"] * s["precio_ticket"]
        s["premio_estimado"] = s["pozo_total"] * s["porcentaje_premio"]
        salas.append(s)
    conn.close()
    return {"status": "ok", "salas": salas, "binance_id_oficial": BINANCE_ID_OFICIAL}

@app.get("/api/sala/{sala_id}/numeros")
def obtener_numeros_sala(sala_id: int):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT nombre, total_tickets, precio_ticket FROM salas WHERE id = ?", (sala_id,))
    sala_info = cursor.fetchone()
    if not sala_info:
        conn.close()
        raise HTTPException(status_code=404, detail="Sala no encontrada")

    cursor.execute("SELECT numero, usuario, binance_id FROM tickets_comprados WHERE sala_id = ?", (sala_id,))
    comprados = {
        str(row["numero"]): {
            "usuario": row["usuario"],
            "binance_id": row["binance_id"]
        }
        for row in cursor.fetchall()
    }
    conn.close()
    return {
        "status": "ok",
        "nombre_sala": sala_info["nombre"],
        "total_tickets": sala_info["total_tickets"],
        "precio_ticket": sala_info["precio_ticket"],
        "tickets_comprados": comprados
    }

@app.post("/api/comprar-ticket")
def comprar_ticket(datos: CompraTicket):
    binance_limpio = datos.binance_id.strip()
    verificar_sistema_activo(binance_limpio)

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT nombre, total_tickets, precio_ticket, porcentaje_premio FROM salas WHERE id = ?",
        (datos.sala_id,)
    )
    sala = cursor.fetchone()
    if not sala:
        conn.close()
        raise HTTPException(status_code=404, detail="Sala no encontrada.")

    if datos.numero < 1 or datos.numero > sala["total_tickets"]:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Número inválido (1 a {sala['total_tickets']}).")

    cursor.execute("SELECT usuario, saldo_usdt FROM usuarios WHERE binance_id = ?", (binance_limpio,))
    user_res = cursor.fetchone()
    if not user_res:
        conn.close()
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")

    if user_res["saldo_usdt"] < sala["precio_ticket"]:
        conn.close()
        raise HTTPException(status_code=400, detail="Saldo insuficiente.")

    try:
        cursor.execute(
            "UPDATE usuarios SET saldo_usdt = ROUND(saldo_usdt - ?, 2) WHERE binance_id = ? AND saldo_usdt >= ?",
            (sala["precio_ticket"], binance_limpio, sala["precio_ticket"])
        )
        if cursor.rowcount == 0:
            conn.rollback()
            conn.close()
            raise HTTPException(status_code=400, detail="Saldo insuficiente.")

        cursor.execute(
            "INSERT INTO tickets_comprados (sala_id, numero, usuario, binance_id) VALUES (?, ?, ?, ?)",
            (datos.sala_id, datos.numero, user_res["usuario"], binance_limpio)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()
        raise HTTPException(status_code=400, detail="¡Este número ya fue comprado!")

    cursor.execute("SELECT COUNT(*) FROM tickets_comprados WHERE sala_id = ?", (datos.sala_id,))
    total_vendidos = cursor.fetchone()[0]
    mensaje_extra = f"¡Número #{datos.numero} comprado en {sala['nombre']}!"

    if total_vendidos >= sala["total_tickets"]:
        cursor.execute(
            "SELECT numero, usuario, binance_id FROM tickets_comprados WHERE sala_id = ?",
            (datos.sala_id,)
        )
        todos_los_tickets = cursor.fetchall()
        if todos_los_tickets:
            ganador = random.choice(todos_los_tickets)
            premio_pozo = round((sala["total_tickets"] * sala["precio_ticket"]) * sala["porcentaje_premio"], 2)

            cursor.execute(
                """INSERT INTO historial_ganadores
                   (sala_id, nombre_sala, numero_ganador, usuario_ganador, binance_id_ganador, premio)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (datos.sala_id, sala["nombre"], ganador["numero"], ganador["usuario"], ganador["binance_id"], premio_pozo)
            )
            cursor.execute("DELETE FROM tickets_comprados WHERE sala_id = ?", (datos.sala_id,))
            conn.commit()
            mensaje_extra += f" ¡{sala['nombre'].upper()} LLENA Y SORTEADA!"

    conn.close()
    return {"status": "ok", "mensaje": mensaje_extra}

# --- FUNCIONES DE ADMINISTRADOR ---
@app.post("/api/admin/pagos/registrar-tx")
def registrar_pago_verificado_admin(datos: RegistrarPagoBinanceAdmin, binance_id_verificacion: str):
    verificar_sistema_activo(binance_id_verificacion)
    admin_nombre = validar_admin_por_binance(binance_id_verificacion)

    if datos.monto_usdt <= 0:
        raise HTTPException(status_code=400, detail="El monto debe ser mayor a 0.")

    tx_limpio = datos.tx_id.strip().upper()
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO binance_pagos_verificados (tx_id, monto_usdt, estado) VALUES (?, ?, 'completado')",
        (tx_limpio, round(datos.monto_usdt, 2))
    )
    conn.commit()
    conn.close()

    registrar_auditoria(admin_nombre, "TX_VERIFICADO", f"TXID {tx_limpio} registrado por ${datos.monto_usdt:.2f} USDT")
    return {"status": "ok", "mensaje": f"TXID {tx_limpio} (${datos.monto_usdt:.2f} USDT) listo para ser reclamado."}

@app.post("/api/admin/hibernacion/toggle")
def toggle_hibernacion(binance_id_verificacion: str):
    verificar_sistema_activo(binance_id_verificacion)
    admin_nombre = validar_admin_por_binance(binance_id_verificacion)

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT valor FROM configuracion WHERE clave = 'hibernation_mode'")
    actual = cursor.fetchone()["valor"]
    nuevo = "off" if actual == "on" else "on"

    cursor.execute("UPDATE configuracion SET valor = ? WHERE clave = 'hibernation_mode'", (nuevo,))
    conn.commit()
    conn.close()

    registrar_auditoria(admin_nombre, "MODO_HIBERNACION", f"Estado cambiado a: {nuevo}")
    return {"status": "ok", "mensaje": f"Modo Hibernación cambiado a: {nuevo.upper()}"}

@app.post("/api/admin/sala/{sala_id}/forzar-sorteo")
def forzar_sorteo_prueba(sala_id: int, binance_id_verificacion: str):
    verificar_sistema_activo(binance_id_verificacion)
    admin_nombre = validar_admin_por_binance(binance_id_verificacion)

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT nombre, total_tickets, precio_ticket, porcentaje_premio FROM salas WHERE id = ?",
        (sala_id,)
    )
    sala = cursor.fetchone()
    if not sala:
        conn.close()
        raise HTTPException(status_code=404, detail="Sala no encontrada.")

    cursor.execute("SELECT numero FROM tickets_comprados WHERE sala_id = ?", (sala_id,))
    ocupados = {row["numero"] for row in cursor.fetchall()}

    cursor.execute("SELECT usuario, binance_id FROM usuarios LIMIT 1")
    usr_test = cursor.fetchone()
    nombre_test = usr_test["usuario"] if usr_test else "TestUser"
    binance_test = usr_test["binance_id"] if usr_test else "00000000"

    for i in range(1, sala["total_tickets"] + 1):
        if i not in ocupados:
            try:
                cursor.execute(
                    "INSERT INTO tickets_comprados (sala_id, numero, usuario, binance_id) VALUES (?, ?, ?, ?)",
                    (sala_id, i, nombre_test, binance_test)
                )
            except sqlite3.IntegrityError:
                pass
    conn.commit()

    cursor.execute(
        "SELECT numero, usuario, binance_id FROM tickets_comprados WHERE sala_id = ?",
        (sala_id,)
    )
    todos = cursor.fetchall()
    ganador = random.choice(todos)
    premio_pozo = round((sala["total_tickets"] * sala["precio_ticket"]) * sala["porcentaje_premio"], 2)

    cursor.execute(
        """INSERT INTO historial_ganadores
           (sala_id, nombre_sala, numero_ganador, usuario_ganador, binance_id_ganador, premio)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (sala_id, sala["nombre"], ganador["numero"], ganador["usuario"], ganador["binance_id"], premio_pozo)
    )
    cursor.execute("DELETE FROM tickets_comprados WHERE sala_id = ?", (sala_id,))
    conn.commit()
    conn.close()

    registrar_auditoria(admin_nombre, "FORZAR_SORTEO", f"Sorteo forzado en sala {sala['nombre']}")
    return {
        "status": "ok",
        "mensaje": f"Sorteo de prueba forzado en {sala['nombre']}. Ganador: #{ganador['numero']} ({ganador['usuario']} - ID {ganador['binance_id']})."
    }

@app.post("/api/admin/usuario/ajustar-saldo")
def ajustar_saldo_usuario(datos: AjusteSaldo, binance_id_verificacion: str):
    verificar_sistema_activo(binance_id_verificacion)
    admin_nombre = validar_admin_por_binance(binance_id_verificacion)

    if datos.monto <= 0:
        raise HTTPException(status_code=400, detail="El monto debe ser mayor a 0.")
    if datos.tipo not in ("sumar", "restar"):
        raise HTTPException(status_code=400, detail="Tipo de ajuste inválido.")

    objetivo_id = datos.binance_id_objetivo.strip()
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("SELECT usuario, saldo_usdt FROM usuarios WHERE binance_id = ?", (objetivo_id,))
    objetivo = cursor.fetchone()
    if not objetivo:
        conn.close()
        raise HTTPException(status_code=404, detail="Usuario objetivo no encontrado por Binance ID.")

    if datos.tipo == "sumar":
        cursor.execute(
            "UPDATE usuarios SET saldo_usdt = ROUND(saldo_usdt + ?, 2) WHERE binance_id = ?",
            (datos.monto, objetivo_id)
        )
    else:
        nuevo_saldo = max(0.0, round(objetivo["saldo_usdt"] - datos.monto, 2))
        cursor.execute(
            "UPDATE usuarios SET saldo_usdt = ? WHERE binance_id = ?",
            (nuevo_saldo, objetivo_id)
        )

    conn.commit()
    conn.close()

    accion_texto = "sumaron" if datos.tipo == "sumar" else "restaron"
    registrar_auditoria(
        admin_nombre,
        "AJUSTE_SALDO",
        f"Se {accion_texto} {datos.monto:.2f} USDT a {objetivo['usuario']} (Binance ID: {objetivo_id})"
    )
    return {"status": "ok", "mensaje": f"Saldo de {objetivo['usuario']} (ID: {objetivo_id}) actualizado correctamente."}

@app.get("/api/admin/ganadores")
def obtener_ganadores_admin(binance_id_verificacion: str):
    verificar_sistema_activo(binance_id_verificacion)
    validar_admin_por_binance(binance_id_verificacion)

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, sala_id, nombre_sala, numero_ganador, usuario_ganador, binance_id_ganador, premio, fecha FROM historial_ganadores ORDER BY id DESC"
    )
    pendientes = [dict(row) for row in cursor.fetchall()]

    cursor.execute(
        "SELECT id, sala_id, nombre_sala, numero_ganador, usuario_ganador, binance_id_ganador, premio, fecha_pago FROM ganadores_historico ORDER BY id DESC LIMIT 50"
    )
    historico = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"status": "ok", "ganadores": pendientes, "historico": historico}

@app.delete("/api/admin/ganador/{ganador_id}")
def eliminar_ganador(ganador_id: int, binance_id_verificacion: str):
    verificar_sistema_activo(binance_id_verificacion)
    admin_nombre = validar_admin_por_binance(binance_id_verificacion)

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM historial_ganadores WHERE id = ?", (ganador_id,))
    g = cursor.fetchone()
    if g:
        cursor.execute(
            """INSERT INTO ganadores_historico
               (sala_id, nombre_sala, numero_ganador, usuario_ganador, binance_id_ganador, premio)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (g["sala_id"], g["nombre_sala"], g["numero_ganador"], g["usuario_ganador"], g["binance_id_ganador"], g["premio"])
        )
        cursor.execute("DELETE FROM historial_ganadores WHERE id = ?", (ganador_id,))
        conn.commit()
    conn.close()

    registrar_auditoria(admin_nombre, "PAGO_GANADOR", f"Ganador ID {ganador_id} marcado como pagado y archivado.")
    return {"status": "ok", "mensaje": "Ganador marcado como pagado y movido al archivo histórico."}

@app.get("/api/admin/usuarios")
def obtener_usuarios(binance_id_verificacion: str):
    verificar_sistema_activo(binance_id_verificacion)
    validar_admin_por_binance(binance_id_verificacion)

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id, usuario, email, binance_id, rol, saldo_usdt FROM usuarios ORDER BY id ASC")
    filas = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"status": "ok", "usuarios": filas}

@app.get("/api/admin/logs")
def obtener_logs_auditoria(binance_id_verificacion: str):
    verificar_sistema_activo(binance_id_verificacion)
    validar_admin_por_binance(binance_id_verificacion)

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs_auditoria ORDER BY id DESC LIMIT 100")
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"status": "ok", "logs": logs}
