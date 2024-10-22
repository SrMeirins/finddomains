# 🔍 `finddomains` - Herramienta para Descubrir Subdominios 🌐

¡Bienvenido a **`finddomains`**! 🎉 Esta es una herramienta para buscar subdominios asociados a un dominio específico utilizando múltiples fuentes. Es ideal para **reconocimiento pasivo** durante auditorías de seguridad y exploraciones OSINT.

## 🚀 Funcionalidades

- **Múltiples Fuentes:** Obtén subdominios desde varias APIs conocidas y servicios públicos.
- **Fácil de Usar:** Solo necesitas un comando para iniciar tu búsqueda.
- **Resultados Detallados:** Archivos de salida con información clara y organizada sobre los subdominios encontrados.

## ⚙️ Instalación

Para comenzar a usar la herramienta, sigue estos pasos:

1. Clona el repositorio:
```bash
git clone https://github.com/tu-usuario/finddomains.git
cd finddomains
```
2. Instala los requisitos:

```bash
pip install -r requirements.txt
```

> **Asegúrate de tener configuradas tus claves de API en `APIs.yaml` (es necesario que el archivo se llame exactamente así).**

## 📋 Uso
```bash
python finddomains.py -d dominio.com
```
Ejemplo:

```bash
python finddomains.py -d example.com
```
La herramienta generará dos archivos:

*example.com_domains.txt*: Lista de subdominios encontrados.

*example.com_domains_with_sources.txt*: Lista detallada con las fuentes de cada subdominio.

## 📦 Fuentes de Subdominios

Actualmente, la herramienta utiliza las siguientes fuentes para recolectar subdominios:

🔹 crt.sh

🔹 SecurityTrails (requiere API Key)

🔹 AlienVault OTX

🔹 VirusTotal (requiere API Key)

🔹 CertSpotter


## 🛠 Futuras Mejoras

Se agregarán más fuentes públicas y APIs a medida que avancemos en el desarrollo. ¡Mantente atento para nuevas actualizaciones! 🚀

## 📄 Configuración de APIs

Para usar esta herramienta, necesitas proporcionar claves API para ciertos servicios en el archivo `APIs.yaml`. Crea este archivo en la raíz de tu directorio donde tengas la herramienta y agrégale las claves necesarias:

```yaml
securitytrails:
  api_key: "TU_API_KEY_AQUI"
virustotal:
  api_key: "TU_API_KEY_AQUI"
```

## 📝 Contribuir
¡Nos encantaría recibir tus contribuciones! Si deseas agregar más fuentes o mejorar la funcionalidad existente, por favor, abre un issue o envía un pull request.

Haz un fork del proyecto.
Crea una nueva rama: `git checkout -b feature/nueva-funcionalidad`

Realiza tus cambios y haz un commit: `git commit -m 'Añadir nueva funcionalidad'`

Empuja los cambios a tu fork: `git push origin feature/nueva-funcionalidad`

Abre un pull request en este repositorio.


## 📜 Licencia
Este proyecto está bajo la licencia MIT. Consulta el archivo LICENSE para más detalles.

## 💬 Contacto
Creado por: SrMeirins
¡No dudes en seguirme y contribuir! 🛠
