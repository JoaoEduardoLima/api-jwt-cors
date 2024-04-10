# Projeto de Estudo API

Este projeto foi desenvolvido para fins de estudos. A API recebe um login com email e senha que então busca no banco de dados a partir do email digitado e, se encontrado, compara a senha para saber se está válido. 

**Observação:** A senha salva no banco de dados encontra-se encriptada.

Com todos os dados corretos, a API gera um token JWT com expiração de 5 minutos. Quando autenticado, o usuário tem acesso ao endpoint para usuários autenticados e outro endpoint para logout, que invalida o token. 

Para invalidar o token, foi adotada a estratégia de gravar no banco de dados o jti do token que não terá mais acesso (id), configurado com TTL de 5 minutos.

## Endpoints

- `/login`: Recebe um login com email e senha.
- `/api/v1`: Acesso para usuários autenticados.
- `/api/v1/logout`: Invalida o token do usuário.

## Tecnologias Utilizadas

- Banco de Dados: Cassandra (NoSQL)
- Autenticação: JWT
- Linguagem: Clojure

## Como Rodar o Projeto
No diretório raiz do projeto

```
docker-compose up
```

```
docker run -it --rm --name clojure -v %cd%:/work -w /work --env-file=./src/api_jwt_cors/.env -p 3010:3010 clojure bash
```
```
lein run
```

## Links para Testes

[swagger](http://localhost)

[web](http://localhost:8081)