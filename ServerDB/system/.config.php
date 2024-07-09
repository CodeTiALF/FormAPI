<?php
    $ip_liberado = 'XXX.XXX.XXX.XXX'; // IP permitido para enviar o formulário
    $segundos_limite = 60 * [minutos]; // Define um tempo entre as gravaçoes do mesmo visitante
    
    // Configurações do banco de dados
    $host = 'localhost';
    $db   = 'FormAPI';
    $user = 'FormAPI';
    $pass = '123456';
    $charset = 'utf8mb4';
    $port = '3306';
    
    // Chave de criptografia para os dados a serem armazenados no banco de dados
    $chave_banco = '123456789012345678901234567890';
