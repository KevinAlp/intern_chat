# Internal TCP Chat (WIP)

## Présentation

Ce projet est un **serveur de messagerie interne** en Python, basé sur une architecture client/serveur TCP.

L’objectif est de comprendre et mettre en pratique les bases du réseau côté système :
- sockets TCP
- gestion de plusieurs clients
- protocole applicatif simple
- gestion des erreurs réseau
- arrêt propre d’un serveur

Le projet est pensé comme une **base** pour aller plus tard vers de la communication audio.

---

## Ce que fait le projet pour le moment

- un serveur TCP accepte plusieurs clients
- chaque client choisit un nom d’utilisateur
- les utilisateurs peuvent s’envoyer des messages privés
- le serveur route les messages entre les clients
- les connexions et déconnexions sont loggées
- arrêt propre du serveur avec Ctrl+C

---

## Ce qui va être fait :

- pas de chiffrement
- pas de base de données
- pas d’interface graphique
- pas de persistance des messages
- pas encore d’audio

Le but est de rester concentré sur le réseau et la logique serveur.

---

## Protocole utilisé

Le protocole est volontairement simple et textuel.  
Tous les messages sont en UTF-8 et terminés par un retour à la ligne.

### Commandes client → serveur
