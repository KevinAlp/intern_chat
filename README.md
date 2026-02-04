# Internal TCP Chat

Serveur/client TCP en Python pour messagerie privée 1:1, avec authentification, persistance SQLite, commandes de modération, accusés de réception/lecture, et TLS optionnel.

## Fonctionnalités

- authentification `AUTH` (création auto du compte à la première connexion)
- messages privés `MSG <user> <message>`
- messages hors-ligne (stockés puis livrés à la reconnexion)
- accusés `DELIVERED` et `READ`
- historique `HISTORY`
- blocage/déblocage d’utilisateurs (`BLOCK` / `UNBLOCK`)
- limitation de débit anti-spam côté serveur
- notifications présence (`INFO user_online`, `INFO user_offline`)
- transport TLS optionnel

## Lancer le serveur

```bash
python3 -m src.messaging.server --host 0.0.0.0 --port 9000 --db-path ./data/chat.db
```

Avec TLS :

```bash
python3 -m src.messaging.server \
  --host 0.0.0.0 \
  --port 9000 \
  --db-path ./data/chat.db \
  --tls-cert ./certs/server.crt \
  --tls-key ./certs/server.key
```

## Lancer le client

Sans TLS :

```bash
python3 -m src.messaging.client --host 127.0.0.1 --port 9000 alice
```

Avec TLS :

```bash
python3 -m src.messaging.client --tls --ca-cert ./certs/server.crt --host 127.0.0.1 --port 9000 alice
```

Pour test local avec certificat autosigné non vérifié :

```bash
python3 -m src.messaging.client --tls --tls-insecure --host 127.0.0.1 --port 9000 alice
```

Le client demande le mot de passe en interactif si `--password` n’est pas fourni.

## Protocole v1

Tous les messages sont des lignes UTF-8 terminées par `\n`.

### Client → serveur

- `HELLO 1`
- `AUTH <username> <password>`
- `MSG <target_username> <message>`
- `LIST`
- `HISTORY <username> [limit]`
- `READ <message_id>`
- `BLOCK <username>`
- `UNBLOCK <username>`
- `PING`
- `QUIT`

### Serveur → client

- `OK <message>`
- `ERROR <code> <reason>`
- `INFO <message>`
- `FROM <message_id> <sender> <timestamp> <message>`
- `DELIVERED <message_id>`
- `READ <message_id> <username>`
- `PONG`

## Commandes interactives client

Le client accepte des raccourcis :

- `/msg <user> <message>`
- `/list`
- `/history <user> [limit]`
- `/block <user>`
- `/unblock <user>`
- `/ping`
- `/quit`
- `/help`

Les commandes protocole brutes (`MSG ...`, `LIST`, etc.) fonctionnent aussi.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Limites actuelles

- pas de chiffrement de bout en bout (le serveur peut lire les messages)
- gestion des mots de passe simple (PBKDF2, sans rotation/2FA)
- pas d’interface graphique
