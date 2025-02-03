# azure-waf-rule-generator

## Uso

### Comando
Ejecutar el siguiente comando para crear la regla de bloque de IPs.

```
./script.sh my-resource-group my-waf-policy my-ip-rules blocked-ips.txt
```

### Archivo
A continuación, se muestra un ejemplo de un archivo con la lista de IPs a bloquear.

```
# Ejemplo de archivo (blocked-ips.txt):
192.168.1.1
10.0.0.0/24
172.16.0.1
```