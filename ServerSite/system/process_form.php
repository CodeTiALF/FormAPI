<?php
/*
* Envio de Formulário com Criptografia e Sanitização
* 
* Este script processa os dados de um formulário de contato, sanitiza os dados de entrada,
* criptografa os dados e os envia para um servidor remoto via HTTP POST.
* 
* Autor: Andre Filus
* Email: andre@andrefilus.com.br
* 2024-07-07 versão 1.0
* 
* Licença:
* Este código é disponibilizado sob a licença de uso e modificação, desde que os créditos
* ao autor original, Andre Filus, sejam mantidos.
* 
* Instruções de Uso:
* 1. Configure o formulário HTML para enviar dados via POST para este script.
* 2. Ajuste o endereço da API conforme necessário.
* 3. Certifique-se de que a extensão OpenSSL do PHP esteja ativada no servidor.
* 4. Coloque este script no diretório apropriado do seu servidor web.
* 
* $_POST['nome']
* $_POST['email']
* $_POST['telefone']
* $_POST['mensagem']
* $_POST['consentimento']) ? 'Sim' : 'Não'
*
* É indispensável que o HTML da política de privacidade e sua URL sejam fornecidos. Além 
* disso, a informação do IP do visitante deve ser capturada.
* Caso algum dos itens do $_POST seja modificado ou omitido, a API não realizará a gravação
* no banco de dados para atender às exigências da LGPD.
*
*/

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Endereço da API
    $url_API = 'https://[site]/FormAPI/apiFromPublic.php';

    // Função para sanitizar dados manualmente
    function manual_sanitize($data) {
        $patterns = [
            '/<\?/',  // Remove 
            '/\?>/',  // Remove 
            '/{/',    // Remove 
            '/}/',    // Remove 
            '/%%/'    // Remove 
        ];
        return preg_replace($patterns, '', $data);
    }

    // Função para sanitizar dados com htmlspecialchars
    function sanitize_input($data) {
        return htmlspecialchars(stripslashes(trim($data)), ENT_QUOTES, 'UTF-8');
    }

    // Captura e sanitiza os dados do formulário antes da criptografia
    $nome = sanitize_input(manual_sanitize(substr($_POST['nome'], 0, 50)));
    $email = sanitize_input(manual_sanitize(substr($_POST['email'], 0, 50)));
    $telefone = sanitize_input(manual_sanitize(substr($_POST['telefone'], 0, 15)));
    $mensagem = sanitize_input(manual_sanitize(substr($_POST['mensagem'], 0, 1000)));
    $consentimento = isset($_POST['consentimento']) ? 'Sim' : 'Não';

    // Captura a data e hora atual
    $data_hora = date("Y-m-d H:i:s");

    // Captura o IP do visitante
    $ip = $_SERVER['REMOTE_ADDR'];

    // Captura a URL da página que enviou o formulário
    $url_origem = $_SERVER['HTTP_REFERER'];

    // Dominio do site
    $dominio_site = $_SERVER['HTTP_HOST'];

    // URL completa do site
    $url_site = (isset($_SERVER['HTTPS']) ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";

    // URL completa da política de privacidade
    // $url_politica = (isset($_SERVER['HTTPS']) ? "https" : "http") . "://$_SERVER[HTTP_HOST]/politica.html";
    $url_politica = "https://[site]/privacidade.php";

    // IP do servidor
    $ip_servidor = $_SERVER['SERVER_ADDR'];

    // Carrega o texto da política de privacidade
    $texto_da_politica = file_get_contents($url_politica);

    // Gerar chave de criptografia a partir da hora, minuto e segundo
    $hora_minuto_segundo = date("His");  // Obtém apenas a hora, minuto e segundo
    $chave = strrev($hora_minuto_segundo);  // Inverte a sequência numérica

    // Criptografia dos dados sanitizados
    $cipher = "aes-256-cbc";  // Algoritmo de criptografia
    $encrypted_nome = openssl_encrypt($nome, $cipher, $chave, 0);
    $encrypted_email = openssl_encrypt($email, $cipher, $chave, 0);
    $encrypted_telefone = openssl_encrypt($telefone, $cipher, $chave, 0);
    $encrypted_mensagem = openssl_encrypt($mensagem, $cipher, $chave, 0);
    $encrypted_ip = openssl_encrypt($ip, $cipher, $chave, 0);

    // Dados a serem enviados para o outro servidor
    $postData = http_build_query([
        'encrypted_nome' => $encrypted_nome,
        'encrypted_email' => $encrypted_email,
        'encrypted_telefone' => $encrypted_telefone,
        'encrypted_mensagem' => $encrypted_mensagem,
        'encrypted_ip' => $encrypted_ip,
        'dominio_site' => $dominio_site,
        'url_origem' => $url_origem,
        'url_site' => $url_site,
        'url_politica' => $url_politica,
        'ip_servidor' => $ip_servidor,
        'data_hora' => $data_hora,
        'texto_da_politica' => $texto_da_politica
    ]);

    // Configuração do contexto para o POST
    $contextOptions = [
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/x-www-form-urlencoded\r\n" .
                        "Content-Length: " . strlen($postData) . "\r\n",
            'content' => $postData,
        ]
    ];
    $context = stream_context_create($contextOptions);

    // Envio dos dados para o outro servidor
    $fp = @fopen($url_API, 'r', false, $context);
    $response = false;
    if ($fp) {
        $response = @stream_get_contents($fp);
        fclose($fp);
    }

    if ($response === false) {
        $error = error_get_last();
        $status = 'erro';
        $message =  "Erro ao enviar os dados: " . $error['message'] . " (" .$dominio_site . ")";
    } else {
        // TODO: Testar se o servidor ou o arquivo existe
        $status = 'sucesso';
        $message =  "Resposta do servidor: " . $response . " (" .$dominio_site . ")";
        
    }
    // Redireciona para a URL especificada com o status
    header("Location: https://apiformsite.imobiliariacidadeimoveis.com.br/FormAPI/form.html?status=$status&message=$message");
    exit();
}
?>
