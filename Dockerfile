FROM ubuntu:17.10

ARG DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# install apt-fast
RUN apt-get update && \
    apt-get install -y -f software-properties-common python-software-properties && \
    add-apt-repository ppa:apt-fast/stable && \
    apt-get update && \
    apt-get -y install apt-fast

ENV AG apt-fast

# install packages
RUN $AG install -y python3 python3-dev python3-pip
RUN $AG install -y telnet

# Create non-root user
RUN groupadd -r user && \
    useradd -m -r -s /bin/bash -g user user && \
    chmod -R 755 /home/user

# Switch to unprivileged user
USER user
RUN mkdir /home/user/src
WORKDIR /home/user/src
ENV PATH /home/user/.local/bin:$PATH

# install packages first
RUN pip3 install --user --upgrade pip

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

# install code
ADD --chown=user:user . /home/user/src
RUN find . -iname '*.py' -exec chmod u+x '{}' \;

RUN ./setup.py develop --user
