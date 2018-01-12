=============
whoisd-rwhois
=============


Unix whois daemon for restful whois backend.


Install
===========

pyenv install:


git clone https://github.com/pyenv/pyenv.git ~/.pyenv

echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc

echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc

echo -e 'if command -v pyenv 1>/dev/null 2>&1; then\n  eval "$(pyenv init -)"\nfi' >> ~/.bashrc


virtualenv install:


git clone https://github.com/pyenv/pyenv-virtualenv.git $(pyenv root)/plugins/pyenv-virtualenv

echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bashrc

## install bz2 libs

sudo apt-get install zlib1g-dev libbz2-dev

## install python 3.6.4

pyenv install 3.6.4


## create pyenv virtualenv

pyenv virtualenv 3.6.4 whoisd-rwhois

## activate virtualenv

pyenv activate whoisd-rwhois

(whoisd-rwhois-consumer) user@host:  pip install -r requirements.txt

