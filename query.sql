DROP TABLE IF EXISTS leads_site_formulario;
CREATE TABLE leads_site_formulario (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARBINARY(255) NOT NULL,
    email VARBINARY(255) NOT NULL,
    telefone VARBINARY(255) NOT NULL,
    mensagem VARBINARY(255) NOT NULL,
    ip VARBINARY(255) NOT NULL,
    dominio VARCHAR(255) NOT NULL,
    url_origem VARCHAR(255) NOT NULL,
    url_site VARCHAR(255) NOT NULL,
    url_politica VARCHAR(255) NOT NULL,
    ip_servidor VARCHAR(255) NOT NULL,
    data_hora DATETIME NOT NULL,
    texto_da_politica TEXT NOT NULL,
    INDEX (ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SELECT
    id,
    CAST(AES_DECRYPT(nome, UNHEX(SHA2('123456789012345678901234567890', 256))) AS CHAR(50)) AS nome,
    CAST(AES_DECRYPT(email, UNHEX(SHA2('123456789012345678901234567890', 256))) AS CHAR(50)) AS email,
    CAST(AES_DECRYPT(telefone, UNHEX(SHA2('123456789012345678901234567890', 256))) AS CHAR(15)) AS telefone,
    CAST(AES_DECRYPT(mensagem, UNHEX(SHA2('123456789012345678901234567890', 256))) AS CHAR(1000)) AS mensagem,
    CAST(AES_DECRYPT(ip, UNHEX(SHA2('123456789012345678901234567890', 256))) AS CHAR(45)) AS ip,
    dominio,
    url_origem,
    url_site,
    url_politica,
    ip_servidor,
    data_hora,
    texto_da_politica
FROM
    leads_site_formulario;
