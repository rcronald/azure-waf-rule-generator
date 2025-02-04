# azure-waf-rule-generator

## Uso

### Comando
Ejecutar el siguiente comando para crear la regla de bloque de IPs.

```
.\script.ps1 `
    -ResourceGroupName "rg-waf-001" `
    -PolicyName "waf-policy-001" `
    -Subdomain "hello.myapplication.com" `
    -IpListFile "blocked-ips.txt"
```

### Archivo
A continuación, se muestra un ejemplo de un archivo con la lista de IPs a bloquear.

```
# Ejemplo de archivo (blocked-ips.txt):
192.168.1.1
10.0.0.0/24
172.16.0.1
```