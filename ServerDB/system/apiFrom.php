<?php
// Verificar se os dados foram recebidos via POST
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Verificar se o IP do visitante é permitido
    $ip_visitante = $_SERVER['REMOTE_ADDR'];
    include ".config.php";

    if ($ip_visitante !== $ip_liberado) {
        die("Acesso negado. Seu IP $ip_visitante não está autorizado a enviar este formulário.");
    } else {
        // Função para descriptografar dados
        function decrypt_data($data, $chave, $cipher) {
            return openssl_decrypt($data, $cipher, $chave, 0);
        }

        // Função para validar dados
        function validar_dados($dados) {
            foreach ($dados as $key => $value) {
                if (empty($value)) {
                    return "Erro: O campo '$key' está vazio.";
                }
            }
            return null;
        }
        
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
        
        // Algoritmo de criptografia
        $cipher = "aes-256-cbc";

        // Receber e sanitizar os dados do formulário
        $encrypted_nome = filter_input(INPUT_POST, 'encrypted_nome', FILTER_SANITIZE_STRING) ?? '';
        $encrypted_email = filter_input(INPUT_POST, 'encrypted_email', FILTER_SANITIZE_STRING) ?? '';
        $encrypted_telefone = filter_input(INPUT_POST, 'encrypted_telefone', FILTER_SANITIZE_STRING) ?? '';
        $encrypted_mensagem = filter_input(INPUT_POST, 'encrypted_mensagem', FILTER_SANITIZE_STRING) ?? '';
        $encrypted_ip = filter_input(INPUT_POST, 'encrypted_ip', FILTER_SANITIZE_STRING) ?? '';
        $dominio_site = filter_input(INPUT_POST, 'dominio_site', FILTER_SANITIZE_STRING) ?? '';
        $url_origem = filter_input(INPUT_POST, 'url_origem', FILTER_SANITIZE_URL) ?? '';
        $url_site = filter_input(INPUT_POST, 'url_site', FILTER_SANITIZE_URL) ?? '';
        $url_politica = filter_input(INPUT_POST, 'url_politica', FILTER_SANITIZE_URL) ?? '';
        $ip_servidor = filter_input(INPUT_POST, 'ip_servidor', FILTER_SANITIZE_STRING) ?? '';
        $data_hora = filter_input(INPUT_POST, 'data_hora', FILTER_SANITIZE_STRING) ?? '';
        //$texto_da_politica = filter_input(INPUT_POST, 'texto_da_politica', FILTER_SANITIZE_STRING) ?? '';
        $texto_da_politica = manual_sanitize($_POST['texto_da_politica']);

        // Verificar se o formulário foi enviado há mais de 15 segundos
        $data_hora_envio = strtotime($data_hora);
        $data_hora_atual = time(); // Hora atual do servidor
        $intervalo = $data_hora_atual - $data_hora_envio;
        
        if ($intervalo > 15) {
            echo "Erro: O formulário foi enviado há mais de 15 segundos. Tente novamente.";
            exit;
        } else {
            
            // Captura a chave de criptografia a partir da hora, minuto e segundo
            $hora_minuto_segundo = date("His", strtotime($data_hora)); // Pega apenas horas, minutos e segundos
            $chave = strrev($hora_minuto_segundo);
            
            $nome = decrypt_data($encrypted_nome, $chave, $cipher);
            $email = decrypt_data($encrypted_email, $chave, $cipher);
            $telefone = decrypt_data($encrypted_telefone, $chave, $cipher);
            $mensagem = decrypt_data($encrypted_mensagem, $chave, $cipher);
            $ip = decrypt_data($encrypted_ip, $chave, $cipher);
            
            // Limpar caracteres indesejados
            $nome = htmlspecialchars(strip_tags($nome));
            $email = htmlspecialchars(strip_tags($email));
            $telefone = htmlspecialchars(strip_tags($telefone));
            $mensagem = htmlspecialchars(strip_tags($mensagem));
            $ip = htmlspecialchars(strip_tags($ip));
        
            // Validar os dados recebidos
            $erro_validacao = validar_dados([
                'nome' => $nome,
                'email' => $email,
                'telefone' => $telefone,
                'mensagem' => $mensagem,
                'ip' => $encrypted_ip,
                'dominio_site' => $dominio_site,
                'url_origem' => $url_origem,
                'url_site' => $url_site,
                'url_politica' => $url_politica,
                'ip_servidor' => $ip_servidor,
                'data_hora' => $data_hora,
                'texto_da_politica' => $texto_da_politica
            ]);
    
            if ($erro_validacao) {
                echo $erro_validacao;
                exit;
            } else {
            
        
                // Cria uma conexão mysqli
                $mysqli = new mysqli($host, $user, $pass, $db, $port);
                
                // Verifica se houve erro na conexão
                if ($mysqli->connect_error) {
                    die("Erro na conexão com o banco de dados: " . $mysqli->connect_error);
                }
                
                // Configura a conexão para usar o charset UTF-8
                $mysqli->set_charset($charset);
                
                // Verificar se houve um envio recente (nos últimos 15 minutos) deste IP
                $stmt_check = $mysqli->prepare("
                    SELECT data_hora FROM leads_site_formulario 
                    WHERE CAST(AES_DECRYPT(ip, UNHEX(SHA2('$chave_banco', 256))) AS CHAR(45)) = ? 
                    ORDER BY data_hora DESC LIMIT 1
                ");
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
                        $minutos_limite = ceil($interval / 60); // Arredonda para cima o valor em minutos
                        $mensagem_limite = "Você já enviou um formulário nos últimos $minutos_limite minutos. Por favor, tente novamente mais tarde.";
                    }
                }
            
                if (!$can_submit) {
                    echo $mensagem_limite;
                } else {
                    // Preparar a query SQL para inserir os dados no banco
                    $stmt = $mysqli->prepare("
                        INSERT INTO leads_site_formulario (
                            nome, email, telefone, mensagem, ip, dominio, url_origem, url_site, url_politica, ip_servidor, data_hora, texto_da_politica
                        ) VALUES (
                            AES_ENCRYPT(?, UNHEX(SHA2('$chave_banco', 256))),
                            AES_ENCRYPT(?, UNHEX(SHA2('$chave_banco', 256))),
                            AES_ENCRYPT(?, UNHEX(SHA2('$chave_banco', 256))),
                            AES_ENCRYPT(?, UNHEX(SHA2('$chave_banco', 256))),
                            AES_ENCRYPT(?, UNHEX(SHA2('$chave_banco', 256))),
                            ?, ?, ?, ?, ?, ?, ?
                        )
                    ");
            
                    // Vincular os parâmetros
                    $stmt->bind_param('ssssssssssss', 
                        $nome, 
                        $email, 
                        $telefone, 
                        $mensagem, 
                        $ip, 
                        $dominio_site,
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
        }
    }    
} else {
    // echo "Nenhum dado recebido.";
    // Redireciona para a URL especificada
    header("Location: https://imobiliariacidadeimoveis.com.br");
    exit();
}

// Fecha a conexão
$mysqli->close();
?>
