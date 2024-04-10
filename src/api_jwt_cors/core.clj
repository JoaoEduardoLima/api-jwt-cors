(ns api-jwt-cors.core
  (:require
   [api-jwt-cors.db :as db]
   [compojure.core :refer [defroutes context GET POST]]
   [compojure.route :as route]
   [ring.adapter.jetty :as jetty]
   [ring.middleware.cookies :refer [wrap-cookies]]
   [ring.middleware.json :refer [wrap-json-body wrap-json-response]]
   [ring.middleware.multipart-params :refer [wrap-multipart-params]]
   [ring.middleware.params :refer [wrap-params]]
   [buddy.core.codecs :as codecs]
   [buddy.core.mac :as mac]
   [buddy.sign.jwt :as jwt]
   [jumblerg.middleware.cors :refer [wrap-cors]])
  (:gen-class))

;; TODO

;; INFRAESTRUTURA
;; [OK] CRIAR CONEXÃO COM O BANCO DE DADOS
;; [OK] CRIAR TABELA DE USUÁRIOS E INSERIR UM USUÁRIO COM A SENHA DO USUÁRIO CRIPTOGRAFADA
;; [OK] CRIAR DOCKERCOMPOSE PARA O BANCO DE DADOS E SWAGGER E FRONT-END

;; API
;; [OK] CRIAR ROTA DE LOGIN (AUTHENTICATION)
;;        BUSCAR NO BANCO DE DADOS O USUÁRIO PELO LOGIN
;;          - SE O USUÁRIO NÃO EXISTIR, DECODIFICAR COM UMA SENHA FAKE, PARA NÃO DAR PISTAS SOBRE A EXISTÊNCIA DO USUÁRIO (TIMING ATTACK)
;;        DECODIFICAR A SENHA DO USUÁRIO SALVO NO BANCO DE DADOS
;;        COMPARAR A SENHA RECEBIDA COM A SENHA DECODIFICADA
;;          - SE AS SENHAS FOREM IGUAIS, GERAR UM TOKEN JWT
;;          - SE AS SENHAS FOREM DIFERENTES, RETORNAR UM RESPONSE COM STATUS 401
;; [OK] RETORNAR O TOKEN JWT NO RESPONSE DA REQUISIÇÃO HTTP (HEADER AUTHORIZATION: Bearer <token>)
;; [OK] CRIAR ROTA DE PROTEGIDA (AUTHORIZATION)
;;        RECEBER O TOKEN JWT NO HEADER
;;        DECODIFICAR O TOKEN JWT
;;        VERIFICAR SE O TOKEN JWT É VÁLIDO
;;        RETORNAR UM RESPONSE COM STATUS 200 SE O TOKEN FOR VÁLIDO
;;        RETORNAR UM RESPONSE COM STATUS 401 SE O TOKEN NÃO FOR VÁLIDO

;; [OK] CRIAR ROTA DE LOGOUT
;;        INVALIDAR O TOKEN JWT
;;        RETORNAR UM RESPONSE COM STATUS 200

;; [  ] IMPLEMENTAR CORS

;; DOCUMENTAÇÃO
;; [OK] IMPLEMENTAR SWAGGER

;; FRONT-END
;; [OK] CRIAR FRONT-END PARA TESTAR A API (CORS) COM AS ROTAS DE LOGIN, PROTEGIDA E LOGOUT

(def SECRET-KEY (System/getenv "SECRET_KEY"))

(defn senha-encode 
  "codifica a senha do usuário para salvar no banco de dados"
  [senha]
  (-> (mac/hash senha {:key SECRET-KEY :alg :hmac+sha256}) (codecs/bytes->hex)))

(defn senha-valida?
  "decodifica a senha salva no banco de dados e compara com a senha recebida na requisição"
  [senha-req senha-db]
 (mac/verify senha-req (codecs/hex->bytes senha-db)  {:key SECRET-KEY :alg :hmac+sha256}))

(defn claim 
  "cria o claim do token jwt"
  [email]
  (let [time-now (-> (java.util.Date.) (.getTime))]
   {
    :iss "api-jwt-cors"                    ;; issuer (emissor): quem emitiu o token
    :sub email                             ;; subject (assunto): 
    :aud "api-jwt-cors"                    ;; audience (público): quem deve receber o token
    :exp (+ time-now (* 1000 300))         ;; expiration (validade): tempo de vida do token (neste caso 5 minutos)
    :nbf time-now                          ;; not before (não antes): a partir de quando o token é válido
    :iat time-now                          ;; issued at (emitido em): data e hora de emissão do token
    :jti (str (java.util.UUID/randomUUID)) ;; JWT ID (identificador do token)
    })) 
   

(defn handler-ok 
  "retorna um response com status 200"
  [_req]
  {:status 200 :headers {"Content-Type" "application/json"} :body {:msg "Ok"}})

(defn handler-401 
  "retorna um response com status 401"
  [_req]
  {:status 401 :headers {"Content-Type" "application/json"} :body {:msg "Não autorizado!"}})

(defn post-handler-login 
  "rota de login da api"
  [req]
  (let [params (:params req)
        email-req (get params "login")
        user-db (db/select-user email-req)]
    (if user-db
      (let [senha-req (get params "senha")
            senha-db (:senha user-db)]
        (if (senha-valida? senha-req senha-db)
          (let [jwt (jwt/sign (claim email-req) SECRET-KEY)]
            {:status 200
             :headers {"Content-Type" "application/json" "Authorization" (str "Bearer " jwt)}
             :body {:msg "Login efetuado com sucesso!"}})
          (do
            (senha-valida? " " senha-db)
            (handler-401 req))))
      (handler-401 req))))

(defn post-handler-logout 
  "rota de logout da api"
  [req]
  (let [token-req (-> req :headers (get "authorization"))
        token (when token-req (let [[_ token] (re-find #"Bearer (.*)" token-req)] token))
        token-decoded (try
                        (jwt/unsign token SECRET-KEY {:now (-> (java.util.Date.) (.getTime))})
                        (catch Exception e
                          nil))
        email (get token-decoded :sub)
        id-token (:jti token-decoded)]
    (if (and email id-token)
      (do 
        (db/insert-jti-token-logout id-token email)
        (handler-ok req))
      (handler-401 req))))

(defn middleware-auth 
  "middleware de autorização da api"
  [handler]
  (fn [req]
    (let [token-req (-> req :headers (get "authorization"))
          token (when token-req (let [[_ token] (re-find #"Bearer (.*)" token-req)] token))
          token-decoded (try
                          (jwt/unsign token SECRET-KEY {:now (-> (java.util.Date.) (.getTime))})
                          (catch Exception e
                            nil))
          logout? (when token-decoded (db/select-jti (:jti token-decoded)))]
      (if (and token-decoded (not logout?)) 
        (handler req)
        (handler-401 req)))))

(defroutes app
  (GET  "/health" [] handler-ok)
  (POST "/login"  [] post-handler-login)
  (middleware-auth
   (context "/api/v1" []
     (GET    "/"        [] handler-ok)
     (POST    "/logout" [] post-handler-logout)))
  (route/not-found "<h1>Page not found</h1>"))

(defn -main
  "Start the server"
  [& args]
  (jetty/run-jetty (-> app
                       (wrap-params :params)
                       (wrap-json-body {:keywords? true})
                       wrap-json-response
                       wrap-multipart-params
                       wrap-cookies
                       (wrap-cors #"http://localhost"
                                  #"http://localhost:8081"))
                   {:port 3010}))
