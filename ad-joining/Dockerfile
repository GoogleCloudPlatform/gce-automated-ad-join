
FROM gcc:latest as build-cc
ADD /ksetpwd /ksetpwd
RUN cd /ksetpwd && make ksetpwd

FROM python:3.7-slim
ADD /register-computer /register-computer
RUN groupadd -r runner && \
    useradd -rm -g runner runner && \
    mkdir -p /register-computer/kerberos/bin && \
    pip3 install -r /register-computer/requirements.txt --no-cache-dir
COPY --from=build-cc /ksetpwd/ksetpwd /register-computer/kerberos/bin
COPY --from=build-cc /lib/x86_64-linux-gnu/libcom_err.* /register-computer/kerberos/bin/

USER runner
WORKDIR /register-computer

CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 docker:app
