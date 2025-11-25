<?php

/**
 * Traffic Quality Security Manager
 * 
 * @package WaAAp security
 * @author Francisco junior
 * @version 1.0
 * @license MIT
 */
class TrafficSecurityManager
{
    private $blockLowQuality = true;
    private $logFile = 'traffic_security.log';
    
    /**
     * Obtém o IP real do usuário
     */
    public function getUserIP()
    {
        $ipKeys = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_CLIENT_IP',
            'REMOTE_ADDR'
        ];
        
        foreach ($ipKeys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = $_SERVER[$key];
                // Para X-Forwarded-For, pega o primeiro IP
                if ($key === 'HTTP_X_FORWARDED_FOR') {
                    $ips = explode(',', $ip);
                    $ip = trim($ips[0]);
                }
                
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return '0.0.0.0';
    }
    
    /**
     * Obtém o User Agent do usuário
     */
    public function getUserAgent()
    {
        return $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    }
    
    /**
     * Processa a verificação de segurança
     */
    public function processSecurityCheck()
    {
        $userIp = $this->getUserIP();
        $userAgent = $this->getUserAgent();
        
        echo "=== INICIANDO VERIFICAÇÃO DE SEGURANÇA ===\n";
        echo "IP Detectado: $userIp\n";
        echo "User Agent: $userAgent\n";
        echo "==========================================\n\n";
        
        return $this->checkAndProcessTraffic($userIp, $userAgent);
    }
    
    /**
     * Verifica qualidade do tráfego e toma ação baseada no risco
     */
    private function checkAndProcessTraffic($userIp, $userAgent)
    {
        $data = $this->verificarQualidadeTrafico($userIp, $userAgent);
        
        if (!$data || isset($data['error'])) {
            $this->logSecurityEvent("ERRO_API", $userIp, "Falha na verificação da API");
            return $this->handleApiError();
        }
        
        // Exibe resultados detalhados
        $this->displayResults($data);
        
        // Verifica e bloqueia se necessário (baseado apenas em traffic_quality)
        if ($this->shouldBlockTraffic($data)) {
            return $this->blockAccess($data);
        }
        
        return $this->allowAccess($data);
    }
    
    /**
     * Verifica qualidade do tráfego
     */
    private function verificarQualidadeTrafico($userIp, $userAgent)
    {
        $url = "https://www.waaap.net/api.php?ip=" . urlencode($userIp);
        
        $ch = curl_init();
        
        $curlOptions = [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_USERAGENT => $userAgent,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_ENCODING => '',
            CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4,
        ];
        
        curl_setopt_array($ch, $curlOptions);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        
        curl_close($ch);
        
        if ($response === false) {
            $this->logSecurityEvent("CURL_ERROR", $userIp, $curlError);
            return ['error' => 'Erro cURL: ' . $curlError];
        }
        
        if ($httpCode !== 200) {
            $this->logSecurityEvent("HTTP_ERROR", $userIp, "Código: $httpCode");
            return ['error' => "Erro HTTP: $httpCode"];
        }
        
        $data = json_decode($response, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->logSecurityEvent("JSON_ERROR", $userIp, json_last_error_msg());
            return ['error' => 'Erro JSON: ' . json_last_error_msg()];
        }
        
        return $data;
    }
    
    /**
     * Exibe resultados detalhados da análise
     */
    private function displayResults($data)
    {
        echo "=== ANÁLISE DE SEGURANÇA DO TRÁFEGO ===\n";
        echo "IP: " . ($data['ip'] ?? 'N/A') . "\n";
        echo "Qualidade do Tráfego: " . strtoupper($data['traffic_quality'] ?? 'unknown') . "\n";
        echo "ASN: " . ($data['asn'] ?? 'N/A') . "\n";
        echo "Organização: " . ($data['organization'] ?? 'N/A') . "\n";
        echo "Navegador: " . ($data['browser'] ?? 'N/A') . " v" . ($data['browser_version'] ?? 'N/A') . "\n";
        echo "Sistema: " . ($data['os'] ?? 'N/A') . " " . ($data['os_version'] ?? 'N/A') . "\n";
        echo "Dispositivo: " . ($data['device'] ?? 'N/A') . "\n";
        echo "Tipo de Cliente: " . ($data['client_type'] ?? 'N/A') . "\n";
        echo "Cache: " . ($data['cached'] ? 'SIM' : 'NÃO') . "\n";
        echo "Tempo de Processamento: " . ($data['processing_time'] ?? 0) . "ms\n";
        
        // Fatores de Risco (exibe mas não usa para bloqueio)
        if (!empty($data['risk_factors'])) {
            echo "Fatores de Risco:\n";
            foreach ($data['risk_factors'] as $risk) {
                echo "  - $risk\n";
            }
        } else {
            echo "Fatores de Risco: Nenhum detectado\n";
        }
        
        echo "Timestamp: " . ($data['timestamp'] ?? 'N/A') . "\n";
        echo "========================================\n\n";
    }
    
    /**
     * Determina se o tráfego deve ser bloqueado (APENAS por traffic_quality)
     */
    private function shouldBlockTraffic($data)
    {
        if (!$this->blockLowQuality) {
            return false;
        }
        
        // BLOQUEIA APENAS SE traffic_quality FOR "low"
        if (isset($data['traffic_quality']) && $data['traffic_quality'] === 'low') {
            return true;
        }
        
        return false;
    }
    
    /**
     * Bloqueia o acesso
     */
    private function blockAccess($data)
    {
        $reason = "Tráfego de baixa qualidade detectado (traffic_quality: low)";
        
        $this->logSecurityEvent("BLOQUEADO", $data['ip'], $reason);
        
        echo "🚫 ACESSO BLOQUEADO!\n";
        echo "Motivo: $reason\n";
        echo "IP: " . $data['ip'] . "\n";
        echo "Ação: Conexão bloqueada por medidas de segurança\n";
        
        // Envia header HTTP de bloqueio
        if (!headers_sent()) {
            header('HTTP/1.1 403 Forbidden');
            header('Retry-After: 3600');
        }
        
        exit; // Termina a execução
    }
    
    /**
     * Permite o acesso
     */
    private function allowAccess($data)
    {
        $quality = $data['traffic_quality'] ?? 'unknown';
        $this->logSecurityEvent("PERMITIDO", $data['ip'], "Tráfego de qualidade: $quality");
        
        echo "✅ ACESSO PERMITIDO!\n";
        echo "Status: Tráfego verificado e aprovado\n";
        echo "IP: " . $data['ip'] . "\n";
        echo "Qualidade: " . $quality . "\n";
        
        return true;
    }
    
    /**
     * Trata erro da API
     */
    private function handleApiError()
    {
        echo "⚠️  AVISO: Não foi possível verificar a qualidade do tráfego\n";
        echo "Acesso permitido (modo fallback)\n";
        
        return true; // Permite acesso em caso de erro
    }
    
    /**
     * Registra eventos de segurança
     */
    private function logSecurityEvent($action, $ip, $details)
    {
        $timestamp = date('Y-m-d H:i:s');
        $logEntry = "[$timestamp] $action - IP: $ip - $details\n";
        
        file_put_contents($this->logFile, $logEntry, FILE_APPEND | LOCK_EX);
    }
    
    /**
     * Configura se deve bloquear tráfego de baixa qualidade
     */
    public function setBlockLowQuality($block)
    {
        $this->blockLowQuality = (bool)$block;
    }
}

// USO PRÁTICO - COLOCAR NO INÍCIO DO SEU SCRIPT
try {
    $securityManager = new TrafficSecurityManager();
    
    // Processa a verificação de segurança
    // Se o traffic_quality for "low", bloqueia automaticamente
    $securityManager->processSecurityCheck();
    
    // Se chegou aqui, o acesso foi permitido (traffic_quality não é "low")
    echo "\n📝 CONTINUANDO COM A APLICAÇÃO NORMAL...\n";
    
} catch (Exception $e) {
    error_log("Erro no TrafficSecurityManager: " . $e->getMessage());
    echo "Erro no sistema de segurança. Contate o administrador.\n";
}


?>
