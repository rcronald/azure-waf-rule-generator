#!/bin/bash

# Validar parametros de entrada
if [ "$#" -lt 4 ]; then
    echo "Usage: $0 <resource-group> <policy-name> <rule-group-name> <ip-blocked-file>"
    echo "Example: $0 my-resource-group my-waf-policy my-ip-rules blocked-ips.txt"
    exit 1
fi

RESOURCE_GROUP=$1
POLICY_NAME=$2
RULE_GROUP_NAME=$3
IP_LIST_FILE=$4

# Validar si el archivo de IPs existe
if [ ! -f "$IP_LIST_FILE" ]; then
    echo "Error: Archivo '$IP_LIST_FILE' no encontrado"
    exit 1
fi

# Validar si Azure CLI esta instalado
if ! command -v az &> /dev/null; then
    echo "Error: Azure CLI no esta instalado."
    exit 1
fi

# Validar si el usuario esta autenticado a Azure
if ! az account show &> /dev/null; then
    echo "Error: Not logged in to Azure. Please run 'az login' first."
    exit 1
fi


TEMP_RULES_FILE=$(mktemp)
RULE_COUNTER=1


while IFS= read -r IP || [ -n "$IP" ]; do
    # No considerar espacios en blanco o comentarios con #
    [[ -z "$IP" || "$IP" =~ ^[[:space:]]*# ]] && continue
    
    # Validar si la IP tiene formato correcto
    if [[ ! "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
        echo "Warning: IP formato invalido - $IP (skipping)"
        continue
    }
    
    # Crear regla
    RULE_NAME="BlockIP_${RULE_COUNTER}"
    
    echo "Agregando a la lista de denegación: $IP"
    az network application-gateway waf-policy custom-rule create \
        --resource-group "$RESOURCE_GROUP" \
        --policy-name "$POLICY_NAME" \
        --rule-group-name "$RULE_GROUP_NAME" \
        --name "$RULE_NAME" \
        --priority "$((100 + RULE_COUNTER))" \
        --rule-type MatchRule \
        --action Deny \
        --match-conditions IP_MATCH --match-variables REMOTE_ADDR --operator IPMatch --values "$IP" \
        --output none
    
    if [ $? -eq 0 ]; then
        echo "Se agrego correctamente el IP: $IP"
    else
        echo "No se agrego el IP: $IP"
    fi
    
    ((RULE_COUNTER++))
done < "$IP_LIST_FILE"

# Clean up
rm -f "$TEMP_RULES_FILE"

echo "Proceso completo $((RULE_COUNTER - 1)) IPs se agregaron a la politica de denegación del WAF"

