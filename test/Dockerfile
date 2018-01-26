FROM debian:latest
RUN apt-get update > /dev/null
RUN apt-get install -y git python3 python3-pip > /dev/null
ENV LANG C.UTF-8
RUN pip3 install git+https://github.com/nodepy/nodepy.git@develop
RUN nodepy https://nodepy.org/install-pm.py
RUN nodepy --version && nodepy-pm version

WORKDIR /app
COPY . .

WORKDIR /app/test
RUN nodepy-pm install -e ..
ENV PATH=".nodepy/bin:${PATH}"
RUN chmod +x test.sh
ENTRYPOINT bash -c ./test.sh
