FROM ubuntu:18.04

ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8

USER root
# Dependencies
RUN apt-get update && apt-get install -y \
        wget curl sudo tmux gcc cmake python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m lab


# Workshop Requirements
RUN pip3 install angr lief jupyterlab

EXPOSE 8888

# Entrypoint
WORKDIR /home/lab
CMD ["jupyter", "lab", "--ip=0.0.0.0", "--port=8888"]
USER lab
