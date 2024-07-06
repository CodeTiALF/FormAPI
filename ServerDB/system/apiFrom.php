<?php
// Verificar se os dados foram recebidos via POST
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Verificar se o IP do visitante é permitido
    $ip_visitante = $_SERVER['REMOTE_ADDR'];
    include ".config.php";
    if ($ip_visitante !== $ip_liberado) {
        die("Acesso negado. Seu IP não está autorizado a enviar este formulário.");
    } else {
        // Função para descriptografar dados
        function decrypt_data($data, $chave, $cipher) {
            return openssl_decrypt($data, $cipher, $chave, 0);
        }
        
        // Cria uma conexão mysqli
        $mysqli = new mysqli($host, $user, $pass, $db);
        
        // Verifica se houve erro na conexão
        if ($mysqli->connect_error) {
            die("Erro na conexão com o banco de dados: " . $mysqli->connect_error);
        }
        
        // Configura a conexão para usar o charset UTF-8
        $mysqli->set_charset($charset);

        // Algoritmo de criptografia
        $cipher = "aes-256-cbc";
    
        // Receber os dados do formulário e descriptografar
        $encrypted_nome = $_POST['encrypted_nome'] ?? '';
        $encrypted_email = $_POST['encrypted_email'] ?? '';
        $encrypted_telefone = $_POST['encrypted_telefone'] ?? '';
        $encrypted_mensagem = $_POST['encrypted_mensagem'] ?? '';
        $encrypted_ip = $_POST['encrypted_ip'] ?? '';
        $url_origem = $_POST['url_origem'] ?? '';
        $url_site = $_POST['url_site'] ?? '';
        $url_politica = $_POST['url_politica'] ?? '';
        $ip_servidor = $_POST['ip_servidor'] ?? '';
        $data_hora = $_POST['data_hora'] ?? '';
        $texto_da_politica = $_POST['texto_da_politica'] ?? '';
    
        // Captura a chave de criptografia a partir da hora, minuto e segundo
        $hora_minuto_segundo = date("His", strtotime($data_hora)); // Pega apenas horas, minutos e segundos
        $chave = strrev($hora_minuto_segundo);
    
        $nome = decrypt_data($encrypted_nome, $chave, $cipher);
        $email = decrypt_data($encrypted_email, $chave, $cipher);
        $telefone = decrypt_data($encrypted_telefone, $chave, $cipher);
        $mensagem = decrypt_data($encrypted_mensagem, $chave, $cipher);
        $ip = decrypt_data($encrypted_ip, $chave, $cipher);
    
        // Verificar se houve um envio recente (nos últimos 15 minutos) deste IP
        $stmt_check = $mysqli->prepare('
            SELECT data_hora FROM leads_site_formulario WHERE ip = ? ORDER BY data_hora DESC LIMIT 1
        ');
        $stmt_check->bind_param('s', $ip);
        $stmt_check->execute();
        $stmt_check->bind_result($last_submission);
        $stmt_check->fetch();
        $stmt_check->close();
    
        $can_submit = true;
        if ($last_submission) {
            $last_submission_time = strtotime($last_submission);
            $current_time = strtotime($data_hora);
            $interval = $current_time - $last_submission_time;
            $can_submit = ($interval >= $segundos_limite);
    
            if ($interval < 60) {
                $mensagem_limite = "Você já enviou um formulário no último minuto. Por favor, tente novamente mais tarde.";
            } else {
                $minutos_limite = ceil($segundos_limite / 60); // Arredonda para cima o valor em minutos
                $mensagem_limite = "Você já enviou um formulário nos últimos $minutos_limite minutos. Por favor, tente novamente mais tarde.";
            }
        }
    
        if (!$can_submit) {
            echo $mensagem_limite;
        } else {
            // Preparar a query SQL para inserir os dados no banco
            $stmt = $mysqli->prepare('
                INSERT INTO leads_site_formulario (
                    nome, email, telefone, mensagem, ip, url_origem, url_site, url_politica, ip_servidor, data_hora, texto_da_politica
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ');
    
            // Vincular os parâmetros
            $stmt->bind_param('sssssssssss', 
                $nome, 
                $email, 
                $telefone, 
                $mensagem, 
                $ip, 
                $url_origem, 
                $url_site, 
                $url_politica, 
                $ip_servidor, 
                $data_hora, 
                $texto_da_politica
            );
    
            // Executar a query
            if ($stmt->execute()) {
                echo "Dados salvos com sucesso.";
            } else {
                echo "Erro ao salvar os dados: " . $stmt->error;
            }
        }
    }    
} else {
    echo "Nenhum dado recebido.";
}

// Fecha a conexão
$mysqli->close();
?>
