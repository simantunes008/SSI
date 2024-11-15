# Resposta da Questão

## QUESTÃO 1: * Como pode verificar que as chaves fornecidas nos ficheiros mencionados (por exemplo, em MSG_SERVER.key e MSG_SERVER.crt) constituem de facto um par de chaves RSA válido?

Para começar temos de verificar que o valor do módulo RSA da chave privada e o valor do módulo RSA da chave pública são iguais. Após isso podemos afirmar que constituem um par de chaves válido. 
Com o seguinte comando: openssl verify -CAfile MSG_CA.crt MSG_SERVER.crt, verificamos e validamos o certificado.
