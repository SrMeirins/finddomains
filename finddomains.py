import os
import argparse
import re
import json
import yaml
import requests
from colorama import Fore, Style, init
from pwn import log

# Inicializar colorama para soportar colores en Windows
init(autoreset=True)

# Lista para registrar errores durante la ejecución
error_log = []

# Función para mostrar el banner
def show_banner():
    banner = f"""
{Fore.CYAN}###{Style.RESET_ALL}
{Fore.GREEN}#############################
#                           #
#       Herramienta         #
#        finddomains        #
#                           #
#      Creado por:          #
#        SrMeirins          #
#                           #
#  Esta herramienta busca   #
#  subdominios asociados    #
#  a un dominio dado.       #
#############################{Style.RESET_ALL}
{Fore.CYAN}###{Style.RESET_ALL}
"""
    print(banner)

# Expresión regular para validar dominios
DOMAIN_REGEX = r"^[a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,63}$"

# Cargar todas las claves de API desde el archivo YAML
def load_api_keys():
    try:
        with open("APIs.yaml", "r") as file:
            config = yaml.safe_load(file)
            return config
    except FileNotFoundError:
        error_log.append("Error: No se encontró el archivo APIs.yaml")
        return {}

# Obtener subdominios de crt.sh
def get_crtsh_domains(domain):
    task = log.progress("Consultando crt.sh")
    try:
        response = requests.get(f"https://crt.sh/?q={domain}&output=json")
        response.raise_for_status()
        response_json = response.json()
        domains = {entry.get("common_name").replace("*", ""): ["crt.sh"] for entry in response_json}
        task.success("Completado")
        return domains
    except requests.RequestException as e:
        task.failure("Error")
        error_log.append(f"Error al obtener datos de crt.sh: {e}")
        return {}
    except json.JSONDecodeError:
        task.failure("Error")
        error_log.append("Error al procesar el JSON de la respuesta de crt.sh.")
        return {}

# Obtener subdominios de SecurityTrails
def get_securitytrails_domains(domain, api_key):
    task = log.progress("Consultando SecurityTrails")
    if not api_key:
        task.failure("API key no proporcionada")
        error_log.append("No se proporcionó API key para SecurityTrails.")
        return {}
    
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {
            "Content-Type": "application/json",
            "APIKEY": api_key
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        subdomains = {f"{sub}.{domain}": ["SecurityTrails"] for sub in data.get("subdomains", [])}
        task.success("Completado")
        return subdomains
    except requests.RequestException as e:
        task.failure("Error")
        error_log.append(f"Error al obtener datos de SecurityTrails: {e}")
        return {}

# Obtener subdominios de AlienVault OTX
def get_alienvault_domains(domain):
    task = log.progress("Consultando AlienVault OTX")
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        subdomains = {entry.get("hostname"): ["AlienVault OTX"] for entry in data.get("passive_dns", [])}
        task.success("Completado")
        return subdomains
    except requests.RequestException as e:
        task.failure("Error")
        error_log.append(f"Error al obtener datos de AlienVault OTX: {e}")
        return {}

# Obtener subdominios de VirusTotal
def get_virustotal_domains(domain, api_key):
    task = log.progress("Consultando VirusTotal")
    if not api_key:
        task.failure("API key no proporcionada")
        error_log.append("No se proporcionó API key para VirusTotal.")
        return {}
    
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {
            "x-apikey": api_key
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        subdomains = {sub["domain"]: ["VirusTotal"] for sub in data.get("subdomains", [])}
        task.success("Completado")
        return subdomains
    except requests.RequestException as e:
        task.failure("Error")
        error_log.append(f"Error al obtener datos de VirusTotal: {e}")
        return {}

# Combinar resultados de múltiples fuentes y eliminar duplicados
def get_combined_domains(domain, api_keys):
    combined_domains = {}

    # Obtener subdominios de crt.sh
    crtsh_results = get_crtsh_domains(domain)
    for subdomain, sources in crtsh_results.items():
        combined_domains.setdefault(subdomain, []).extend(sources)

    # Obtener subdominios de SecurityTrails
    if "securitytrails" in api_keys and api_keys["securitytrails"].get("api_key"):
        securitytrails_results = get_securitytrails_domains(domain, api_keys["securitytrails"]["api_key"])
        for subdomain, sources in securitytrails_results.items():
            combined_domains.setdefault(subdomain, []).extend(sources)
    else:
        error_log.append("SecurityTrails API key no encontrada o no válida en el archivo APIs.yaml.")
    
    # Obtener subdominios de AlienVault
    alienvault_results = get_alienvault_domains(domain)
    for subdomain, sources in alienvault_results.items():
        combined_domains.setdefault(subdomain, []).extend(sources)

    # Obtener subdominios de VirusTotal
    if "virustotal" in api_keys and api_keys["virustotal"].get("api_key"):
        virustotal_results = get_virustotal_domains(domain, api_keys["virustotal"]["api_key"])
        for subdomain, sources in virustotal_results.items():
            combined_domains.setdefault(subdomain, []).extend(sources)
    else:
        error_log.append("VirusTotal API key no encontrada o no válida en el archivo APIs.yaml.")

    # Eliminar duplicados en las listas de fuentes
    for subdomain in combined_domains:
        combined_domains[subdomain] = list(set(combined_domains[subdomain]))

    return combined_domains

# Guardar resultados en archivos
def save_to_files(filename, results, detailed_filename):
    with open(filename, "w") as file:
        for domain in results:
            file.write(f"{domain}\n")
    os.chmod(filename, 0o600)  # Establecer permisos 600

    with open(detailed_filename, "w") as detailed_file:
        for domain, sources in results.items():
            sources_str = ", ".join(sources)  # Unir las fuentes en una cadena
            detailed_file.write(f"{domain} ({sources_str})\n")
    os.chmod(detailed_filename, 0o600)  # Establecer permisos 600


# Manejar argumentos de línea de comandos
parser = argparse.ArgumentParser(description="Herramienta para encontrar subdominios asociados a un dominio dado.")
parser.add_argument("-d", "--dominio", help="Especifica el dominio para buscar subdominios.")
args = parser.parse_args()

# Mostrar banner
show_banner()

# Obtener el dominio del usuario si no se proporcionó en la línea de comandos
dominio = args.dominio or input(f"{Fore.CYAN}Por favor, introduce el dominio para buscar los subdominios:\nDominio: {Style.RESET_ALL}")

# Validar el dominio ingresado
if not re.match(DOMAIN_REGEX, dominio):
    print(f"{Fore.RED}Error: Has proporcionado un dominio no válido.")
    sys.exit(1)

# Cargar las API keys de todas las fuentes definidas en el archivo YAML
api_keys = load_api_keys()

# Definir los nombres de los archivos de salida
filename = f"./{dominio}_domains.txt"
detailed_filename = f"./{dominio}_domains_with_sources.txt"

# Obtener y procesar dominios de todas las fuentes
print(f"\n{Fore.CYAN}Obteniendo dominios y subdominios asociados para: {Fore.GREEN}{dominio}{Style.RESET_ALL}\n")
result = get_combined_domains(dominio, api_keys)

# Verificar si hay resultados
if not result:
    print(f"{Fore.RED}No se encontraron dominios o subdominios para {Fore.GREEN}{dominio}{Style.RESET_ALL}\n")
else:
    # Guardar los resultados en los archivos
    save_to_files(filename, result, detailed_filename)

    # Mostrar los resultados en líneas separadas
    print(f"\n{Fore.CYAN}Dominios encontrados:{Style.RESET_ALL}")
    for domain in result.keys():
        print(f"{Fore.GREEN}{domain}{Style.RESET_ALL}")

    # Confirmar que se ha guardado en el archivo
    print(f"\n{Fore.CYAN}Los resultados han sido guardados en: {Fore.GREEN}{filename}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Los resultados detallados han sido guardados en: {Fore.GREEN}{detailed_filename}{Style.RESET_ALL}")

# Mostrar errores si los hay
if error_log:
    print(f"\n{Fore.RED}Errores encontrados durante la ejecución:{Style.RESET_ALL}")
    for error in error_log:
        print(f"{Fore.RED}- {error}{Style.RESET_ALL}")