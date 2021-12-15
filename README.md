# Auth490

**This is a proof of concept. It should not be used in production.**

Auth490 is a Peer to Peer Authorization (P2PA) system that uses assymetric cryptography to offer secure data transfers between individuals. The primary goal is to offer a strong standard for vaccination passports. In addition, the system is generic enough for any P2PA applications (employee badges, concert tickets, etc). The end goal would be to have one system for all P2PA situations.

## Research

This research was conducted in at Concordia University for COMP 490 under the supervision of Dr. Thiel. The team was composed of only myself, Alexandre Lavoie. 

The research paper associated to this project can be found here: https://www.overleaf.com/read/jvxsnbkqgpdq . It explores the technologies and flaws of the current state of P2PA and offers a proposal and analysis to this project.

## Installation

This is a relatively simple `Python3` project. All that is required is to install the dependencies. The easiest way to do is the following:

```bash
python3 -m venv ./.venv
source ./.venv/bin/activate.*
pip3 install -r requirements.txt
```

## Running

The infrastructure can be started using the following:

```bash
python3 serve.py
```

This will start the server with a client on http://localhost:5000/. The "instance" that is currently running can be identified by the page url (either `/client` or `/server`) or by the color of the header. In production, these two instances would be separate (one probably being a blockchain and the other a mobile app). 

## Testing

A script was written to test most of the available component. It can be run using the following:

```bash
python3 test.py
```

The usage of every component can be fairly well understood by the large test case.
