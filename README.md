# ✅ WaAAp Security Check

Sistema de Verificação de IP — **WaAAp-Security-Check/1.0**

Ferramenta criada para analisar, validar e filtrar acessos, ajudando a manter
plataformas, links diretos e sistemas de monetização mais seguros e livres de
tráfego suspeito ou automatizado.

---

## 🚀 Funcionalidades
- Verificação de IP em tempo real
- Detecção de padrões suspeitos
- Registro e monitoramento de acessos
- Bloqueio automático de tráfego inválido
- Compatível com integrações externas

---

## 📦 Instalação
1. Clone o repositório:
   ```bash
   git clone https://github.com/seu-usuario/waaap-security-check.git
Como funciona:

✅ Captura automaticamente o IP e User Agent do usuário

✅ Consulta a API para verificar a qualidade do tráfego

✅ Exibe todos os dados retornados pela API

✅ Bloqueia apenas se "traffic_quality": "low"

✅ Permite acesso se "traffic_quality": "high" ou qualquer outro valor

✅ Não considera os risk_factors para bloqueio, apenas exibe

Para usar:

php
// Coloque no início do seu script PHP
require_once 'TrafficSecurityManager.php';
$security = new TrafficSecurityManager();
$security->processSecurityCheck(); // Bloqueia automaticamente se quality = low
Resultado esperado:

Se traffic_quality = "low" → BLOQUEADO

Se traffic_quality = "high" ou "medium" → PERMITIDO

Se API falhar → PERMITIDO (fallback)
