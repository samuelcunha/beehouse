# BeeHouse

## Mecanismo de detecção e prevenção resiliente contra ataques DDOS em redes IoT utilizando honeypots

Universidade Federal de Minas Gerais

Alunos: Samuel Jesus Pereira Cunha e Vitor Fagundes Alves Nogueira

Mentor: José Everaldo de Andrade Junior

Professor: Aldri Luiz dos Santos

Disciplina: Gerência de Redes de Computadores e do Serviços

## Pré requisitos

- Sistema Operacional Linux
- Python 3+
  - Pip
  - Virtualenv


## Instalação

```
git clone git@github.com:samuelcunha/beehouse.git
cd beehouse

virtualenv env
. env/bin/activate
pip install -r requirements.txt

```
## Honeypot
```
cp hotneypot/opencanary.conf ~/opencanary.conf
opencanaryd --start
```

## Detector
```
cd detector
sudo python3 app.py
```

## Simular DDoS

```
cd detector
sudo python3 ddos.py [IP de destino] [Faixa de IP de Origem] [Quantidade de requisições]
```
### Exemplo
```
sudo python3 ddos.py 192.168.2.115 192.168.2. 1000
```
## Registro dos ataques
- Atacantes: 
  - detector/attackers.log
- Ataques registrados:
  - detector/attacks.log
