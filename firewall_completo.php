<?php
declare(strict_types=1);

/**
 * WaAAp-Security-Check/1.0 - Sistema de Verificação de IP
 * 
 * @package    IP Security Suite
 * @author     Francisco junior
 * @version    1.0.0
 * @license    MIT License
 */

final class IPSecurityChecker
{
    private const API_URL = 'https://www.waaap.net/api.php';
    private const TIMEOUT = 10;
    private const USER_AGENT_FALLBACK = 'WaAAp-Security-Check/1.0';

    // Variáveis públicas para acesso direto
    public static $ip;
    public static $status;
    public static $message;
    public static $source;
    public static $country;
    public static $user_agent;
    public static $referer;
    public static $is_api_call;
    
    // Variáveis do dispositivo
    public static $device_browser;
    public static $device_browser_version;
    public static $device_os;
    public static $device_os_version;
    public static $device_device;
    public static $device_device_type;
    public static $device_is_bot;
    public static $device_bot_name;
    
    // Variáveis das verificações
    public static $dataset_exists;
    public static $ml_exists;
    public static $ml_message;
    public static $ml_malicious;
    
    // Variáveis das detecções
    public static $detection_proxy;
    public static $detection_vpn;
    public static $detection_compromised;
    public static $detection_scraper;
    public static $detection_tor;
    public static $detection_hosting;
    public static $detection_anonymous;
    public static $detection_risk;
    public static $detection_timestamp;

    /**
     * Executa verificação completa e popula todas as variáveis
     */
    public static function runCompleteCheck(?string $ip = null): bool
    {
        try {
            $result = self::checkSecurity($ip);
            
            if (isset($result['error'])) {
                self::populateErrorVariables($result);
                return false;
            }

            self::populateAllVariables($result);
            return true;

        } catch (Throwable $e) {
            self::populateErrorVariables([
                'status' => 'error',
                'message' => 'Erro durante a verificação: ' . $e->getMessage(),
                'ip' => $ip ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'
            ]);
            return false;
        }
    }

    /**
     * Verifica a segurança de um IP
     */
    private static function checkSecurity(?string $ip = null): array
    {
        $ipToCheck = self::getValidatedIP($ip);
        
        if (!$ipToCheck) {
            return self::createErrorResponse('IP inválido fornecido', $ip);
        }

        $apiResponse = self::callSecurityAPI($ipToCheck);
        
        if (isset($apiResponse['error'])) {
            return $apiResponse;
        }

        return self::processAPIResponse($apiResponse, $ipToCheck);
    }

    /**
     * Obtém e valida o IP
     */
    private static function getValidatedIP(?string $ip): string
    {
        if ($ip === null) {
            $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? '';
        }

        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
    }

    /**
     * Chama a API de segurança
     */
    private static function callSecurityAPI(string $ip): array
    {
        $url = self::API_URL . '?ip=' . urlencode($ip);
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? self::USER_AGENT_FALLBACK;

        $ch = curl_init();
        
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => self::TIMEOUT,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT      => $userAgent,
            CURLOPT_FAILONERROR    => true
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        
        curl_close($ch);

        if ($error) {
            return self::createErrorResponse("Erro cURL: $error", $ip, ['http_code' => $httpCode]);
        }

        if ($httpCode !== 200) {
            return self::createErrorResponse("HTTP Error: $httpCode", $ip, ['http_code' => $httpCode]);
        }

        return ['response' => $response, 'ip' => $ip];
    }

    /**
     * Processa a resposta da API
     */
    private static function processAPIResponse(array $apiData, string $ip): array
    {
        $data = json_decode($apiData['response'], true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            return self::createErrorResponse(
                'JSON inválido da API', 
                $ip, 
                ['raw_response' => $apiData['response']]
            );
        }

        $data['ip'] = $ip;
        return $data;
    }

    /**
     * Cria resposta de erro padronizada
     */
    private static function createErrorResponse(string $message, string $ip, array $extra = []): array
    {
        return array_merge([
            'status'  => 'error',
            'message' => $message,
            'ip'      => $ip,
            'error'   => true
        ], $extra);
    }

    /**
     * Popula todas as variáveis com os dados da API
     */
    private static function populateAllVariables(array $result): void
    {
        // Informações básicas
        self::$ip = $result['ip'] ?? '';
        self::$status = $result['status'] ?? '';
        self::$message = $result['message'] ?? '';
        self::$source = $result['source'] ?? '';
        self::$country = $result['country'] ?? '';
        self::$user_agent = $result['user_agent'] ?? '';
        self::$referer = $result['referer'] ?? '';
        self::$is_api_call = $result['is_api_call'] ?? false;

        // Informações do dispositivo
        self::$device_browser = $result['device_info']['browser'] ?? '';
        self::$device_browser_version = $result['device_info']['browser_version'] ?? '';
        self::$device_os = $result['device_info']['os'] ?? '';
        self::$device_os_version = $result['device_info']['os_version'] ?? '';
        self::$device_device = $result['device_info']['device'] ?? '';
        self::$device_device_type = $result['device_info']['device_type'] ?? '';
        self::$device_is_bot = $result['device_info']['is_bot'] ?? false;
        self::$device_bot_name = $result['device_info']['bot_name'] ?? '';

        // Verificações de segurança
        self::$dataset_exists = $result['checks']['dataset']['exists'] ?? false;
        self::$ml_exists = $result['checks']['ml']['exists'] ?? false;
        self::$ml_message = $result['checks']['ml']['message'] ?? '';
        self::$ml_malicious = $result['checks']['ml']['malicious'] ?? false;

        // Detecções
        self::$detection_proxy = $result['checks']['ml']['details']['detections']['proxy'] ?? false;
        self::$detection_vpn = $result['checks']['ml']['details']['detections']['vpn'] ?? false;
        self::$detection_compromised = $result['checks']['ml']['details']['detections']['compromised'] ?? false;
        self::$detection_scraper = $result['checks']['ml']['details']['detections']['scraper'] ?? false;
        self::$detection_tor = $result['checks']['ml']['details']['detections']['tor'] ?? false;
        self::$detection_hosting = $result['checks']['ml']['details']['detections']['hosting'] ?? false;
        self::$detection_anonymous = $result['checks']['ml']['details']['detections']['anonymous'] ?? false;
        self::$detection_risk = $result['checks']['ml']['details']['detections']['risk'] ?? 0;
        self::$detection_timestamp = $result['checks']['ml']['details']['timestamp'] ?? 0;
    }

    /**
     * Popula variáveis com dados de erro
     */
    private static function populateErrorVariables(array $errorData): void
    {
        self::$ip = $errorData['ip'] ?? '0.0.0.0';
        self::$status = $errorData['status'] ?? 'error';
        self::$message = $errorData['message'] ?? 'Erro desconhecido';
        self::$source = 'error';
        self::$country = '';
        self::$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        self::$referer = $_SERVER['HTTP_REFERER'] ?? 'direct';
        self::$is_api_call = false;

        // Valores padrão para outras variáveis
        self::$device_browser = 'Unknown';
        self::$device_browser_version = '';
        self::$device_os = 'Unknown';
        self::$device_os_version = '';
        self::$device_device = 'Unknown';
        self::$device_device_type = 'desktop';
        self::$device_is_bot = false;
        self::$device_bot_name = '';

        self::$dataset_exists = false;
        self::$ml_exists = false;
        self::$ml_message = 'Erro na verificação';
        self::$ml_malicious = false;

        self::$detection_proxy = false;
        self::$detection_vpn = false;
        self::$detection_compromised = false;
        self::$detection_scraper = false;
        self::$detection_tor = false;
        self::$detection_hosting = false;
        self::$detection_anonymous = false;
        self::$detection_risk = 0;
        self::$detection_timestamp = time();
    }

    /**
     * Formata valores booleanos para exibição
     */
    public static function formatBoolean(bool $value): string
    {
        return $value ? 'Sim' : 'Não';
    }

    /**
     * Exibe resumo completo das variáveis
     */
    public static function displayVariablesSummary(): void
    {
        echo "=== VARIÁVEIS DE SEGURANÇA DE IP ===\n\n";
        
        echo "🌐 INFORMAÇÕES BÁSICAS:\n";
        echo "IP: " . self::$ip . "\n";
        echo "Status: " . self::$status . "\n";
        echo "Mensagem: " . self::$message . "\n";
        echo "Fonte: " . self::$source . "\n";
        echo "País: " . self::$country . "\n";
        echo "User Agent: " . self::$user_agent . "\n";
        echo "Referer: " . self::$referer . "\n";
        echo "API Call: " . self::formatBoolean(self::$is_api_call) . "\n\n";

        echo "📱 DISPOSITIVO:\n";
        echo "Navegador: " . self::$device_browser . "\n";
        echo "Versão Navegador: " . self::$device_browser_version . "\n";
        echo "Sistema Operacional: " . self::$device_os . "\n";
        echo "Versão SO: " . self::$device_os_version . "\n";
        echo "Dispositivo: " . self::$device_device . "\n";
        echo "Tipo Dispositivo: " . self::$device_device_type . "\n";
        echo "É Bot: " . self::formatBoolean(self::$device_is_bot) . "\n";
        echo "Nome Bot: " . self::$device_bot_name . "\n\n";

        echo "🛡️ VERIFICAÇÕES:\n";
        echo "Dataset Exists: " . self::formatBoolean(self::$dataset_exists) . "\n";
        echo "ML Exists: " . self::formatBoolean(self::$ml_exists) . "\n";
        echo "Mensagem ML: " . self::$ml_message . "\n";
        echo "Malicious: " . self::formatBoolean(self::$ml_malicious) . "\n\n";

        echo "🔍 DETECÇÕES:\n";
        echo "Proxy: " . self::formatBoolean(self::$detection_proxy) . "\n";
        echo "VPN: " . self::formatBoolean(self::$detection_vpn) . "\n";
        echo "Compromised: " . self::formatBoolean(self::$detection_compromised) . "\n";
        echo "Scraper: " . self::formatBoolean(self::$detection_scraper) . "\n";
        echo "Tor: " . self::formatBoolean(self::$detection_tor) . "\n";
        echo "Hosting: " . self::formatBoolean(self::$detection_hosting) . "\n";
        echo "Anonymous: " . self::formatBoolean(self::$detection_anonymous) . "\n";
        echo "Risk Score: " . self::$detection_risk . "\n";
        
        if (self::$detection_timestamp > 0) {
            echo "Timestamp: " . date('d/m/Y H:i:s', self::$detection_timestamp) . "\n";
        }
    }
}

// =============================================================================
// EXECUÇÃO PRINCIPAL
// =============================================================================

// Executar verificação completa
$checkSuccess = IPSecurityChecker::runCompleteCheck();

// Exibir resumo das variáveis
IPSecurityChecker::displayVariablesSummary();

// =============================================================================
// EXEMPLOS DE USO DAS VARIÁVEIS NO SEU CÓDIGO
// =============================================================================

echo "\n=== EXEMPLOS DE USO ===\n";

// 1. Verificar se o IP está bloqueado
if (IPSecurityChecker::$status === 'blocked') {
    echo "🚫 IP BLOQUEADO! Motivo: " . IPSecurityChecker::$message . "\n";
     header('HTTP/1.1 403 Forbidden');
     exit;
}

// 2. Verificar risk score
if (IPSecurityChecker::$detection_risk > 5) {
    echo "⚠️  Risk Score elevado: " . IPSecurityChecker::$detection_risk . "\n";
}

// 3. Verificar se é proxy/VPN
if (IPSecurityChecker::$detection_proxy) {
    echo "⚠️  Proxy detectado!\n";
}

if (IPSecurityChecker::$detection_vpn) {
    echo "⚠️  VPN detectada!\n";
}

// 4. Verificar se é bot
if (IPSecurityChecker::$device_is_bot) {
    echo "🤖 Bot detectado: " . IPSecurityChecker::$device_bot_name . "\n";
}

// 5. Informações do dispositivo para analytics
echo "📊 Dispositivo: " . IPSecurityChecker::$device_browser . " em " . IPSecurityChecker::$device_os . "\n";


// 7. Tomada de decisão baseada em múltiplos fatores
$isSuspicious = IPSecurityChecker::$detection_risk > 7 || 
                IPSecurityChecker::$detection_proxy || 
                IPSecurityChecker::$detection_vpn || 
                IPSecurityChecker::$detection_tor;

if ($isSuspicious) {
    echo "🔒 Acesso suspeito detectado - Reforçar verificação\n";
}