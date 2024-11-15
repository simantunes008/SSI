# Respostas das Questões
## Q2

Se escolhermos um NONCE fixo, isso terá sérias consequências para a segurança da criptografia. A função criptográfica que o gera é previsível, o que significa que sempre produzirá o mesmo resultado para a mesma entrada. Portanto, se o NONCE permanecer constante, quem quiser realizar um ataque pode potencialmente reutilizar comunicações anteriores em ataques de repetição. Isso pode resultar na quebra dos sistemas criptográficos, comprometendo a segurança da informação.
Por isso, é essencial garantir que o NONCE seja único e aleatório para manter a segurança da cifra.

## Q3

Ao aplicar o programa chacha20_int_attack.py nos criptogramas gerados por cfich_aes_cbc.py, o impacto será mais indireto e complexo. Isso ocorre devido ao modo de operação CBC, no qual cada bloco de texto cifrado depende do bloco anterior, tornando a modificação isolada de um bloco menos direta e potencialmente afetando múltiplos blocos subsequentes.

Por outro lado, nos criptogramas produzidos por cfich_aes_ctr.py, o impacto será mais direto. No modo CTR, a modificação do ciphertext resultará em alterações correspondentes no plaintext, devido à operação de XOR. Assim, o ataque pode ser mais eficaz e direto, pois a alteração no ciphertext afeta diretamente o conteúdo decifrado.

Em conclusão, enquanto no CBC o ataque é mais complexo e indireto, no CTR ele é mais direto e potencialmente mais eficaz.

# Relatório do Guião da Semana 4
cfich_chacha20.py: O código define funções para configurar uma chave de criptografia para criptografar um arquivo e descriptografar um arquivo. A função setup gera uma chave aleatória e grava-a num arquivo. A função enc lê um arquivo e a chave, gera um nonce aleatório, cria um cifrador ChaCha20 com a chave e o nonce, criptografa o conteúdo do arquivo e grava o nonce e o texto cifrado em um novo arquivo. A função dec faz o inverso: lê um arquivo e a chave, extrai o nonce e o texto cifrado do arquivo, cria um decifrador ChaCha20 com a chave e o nonce, descriptografa o texto cifrado e grava o texto simples num novo arquivo.

chacha20_int_attck.py: Este código define uma função para realizar um ataque de integridade a um arquivo criptografado. A função attack lê um arquivo criptografado, extrai um segmento do texto cifrado na posição especificada, calcula o XOR desse segmento com um texto conhecido e um novo texto, substitui o segmento no texto cifrado pelo resultado do XOR e grava o nonce e o texto cifrado modificado num novo arquivo.

cfich_aes_cbc.py: Este código define funções para configurar uma chave de criptografia, criptografar um arquivo e descriptografar um arquivo. A função setup gera uma chave aleatória e grava-a num arquivo. A função enc lê um arquivo e uma chave, preenche o texto simples para um múltiplo de 16 bytes, gera um vetor de inicialização (IV) aleatório, cria um cifrador AES com a chave e o IV, criptografa o texto simples preenchido e grava o IV e o texto cifrado em um novo arquivo. A função dec faz o inverso: lê um arquivo e uma chave, extrai o IV e o texto cifrado do arquivo, cria um decifrador AES com a chave e o IV, descriptografa o texto cifrado, remove o preenchimento e grava o texto simples num novo arquivo.

cfich_aes_ctr.py: Este código é semelhante ao anterior, mas usa o modo CTR em vez do modo CBC. O modo CTR usa um nonce (número usado uma vez) em vez de um IV, e não requer preenchimento porque opera em blocos de texto simples de qualquer tamanho. A função enc gera um nonce aleatório, cria um cifrador AES com a chave e o nonce, criptografa o texto simples e grava o nonce e o texto cifrado num novo arquivo. A função dec lê um arquivo e uma chave, extrai o nonce e o texto cifrado do arquivo, cria um decifrador AES com a chave e o nonce, descriptografa o texto cifrado e grava o texto simples num novo arquivo

pbenc_chacha20.py: Este código define funções para criptografar e descriptografar um arquivo usando uma frase secreta em vez de uma chave fixa. A função derive_key usa a função PBKDF2HMAC para derivar uma chave a partir de uma frase secreta e um salt. As funções enc e dec são semelhantes às do código do cfich_chacha20.py, mas usam a função derive_key para obter a chave a partir de uma frase secreta e um salt aleatório (para enc) ou um salt lido do arquivo (para dec).
