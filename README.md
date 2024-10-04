ADVERTENCIA
Esta herramienta debe ser utilizada solo para fines éticos y legales. Asegúrate de tener permiso explícito antes de realizar escaneos o pruebas en cualquier sistema. El autor no se hace responsable del uso indebido de esta herramienta.

Vandal es una herramienta de evaluación de seguridad diseñada para ayudar a los profesionales y entusiastas de la ciberseguridad a identificar vulnerabilidades comunes en aplicaciones web. Esta herramienta proporciona un enfoque simple y efectivo para realizar pruebas de seguridad, enfocándose en áreas críticas que pueden comprometer la integridad y la seguridad de un sitio web.

Requisitos
* Python 3
* Biblioteca requests
* Herramienta nmap

Instalación 
* Git clone https://github.com/44Viciius/Vandal.git
* Cd vandal
* Python3 vandal.py [url]

Opciones
* -h, --help: Muestra la ayuda y las opciones disponibles.
* User-Agent personalizado: Puedes especificar un User-Agent para tus solicitudes HTTP.
* Retraso entre escaneos: Elige un retraso recomendado entre los escaneos para minimizar la posibilidad de ser bloqueado.

* Escaneo de Puertos: 
  Identifica puertos abiertos en el dominio objetivo utilizando Nmap, lo que puede revelar servicios expuestos.
*Comprobación de Encabezados de Seguridad: 
  Verifica la presencia de encabezados de seguridad esenciales, tales como:
* X-Frame-Options
* Content-Security-Policy
* X-XSS-Protection
* Strict-Transport-Security
 
* Detección de Inyección SQL:
Realiza pruebas automatizadas para detectar vulnerabilidades de inyección SQL en la URL especificada, utilizando varias cargas útiles para evaluar la seguridad de la base de datos.

* Detección de Inyección de Comandos:
Prueba la resistencia de la aplicación a ataques de inyección de comandos, utilizando diversas cargas útiles para intentar ejecutar comandos en el servidor.

* Búsqueda de Subdominios: 
Identifica subdominios asociados al dominio objetivo, ampliando el alcance de la evaluación y facilitando la detección de posibles puntos de entrada adicionales.

* Exploración de la Wayback Machine: 
Busca versiones anteriores del sitio web para identificar información sensible que podría haber sido expuesta en el pasado.

* Validación de URLs: 
Comprueba la validez de las URLs proporcionadas para asegurar que son accesibles.

* Detección de Vulnerabilidades de Autenticación: 
Analiza respuestas de autenticación para identificar posibles debilidades en los mecanismos de login.

* Pruebas de Cross-Site Scripting (XSS): 
Evalúa la susceptibilidad a ataques XSS a través de la inyección de cargas útiles específicas en las entradas de URL.

* Recolección de Información: 
Extrae información útil del encabezado de respuesta, como el servidor y la tecnología utilizada, que puede ayudar a identificar vulnerabilidades específicas.

* Detección de CORS (Cross-Origin Resource Sharing): 
Comprueba la configuración de CORS para identificar configuraciones inseguras que podrían permitir solicitudes no autorizadas.
