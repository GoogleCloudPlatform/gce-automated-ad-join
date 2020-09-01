
FROM gcc:latest as build-cc
ADD /ksetpwd /ksetpwd
RUN cd /ksetpwd && make ksetpwd

FROM python:3.7-slim
ADD /register-computer /register-computer
RUN pip3 install -r /register-computer/requirements.txt --no-cache-dir
COPY --from=build-cc /ksetpwd /register-computer/kerberos/bin
COPY --from=build-cc /lib/x86_64-linux-gnu/libcom_err.* /register-computer/kerberos/bin/

WORKDIR /register-computer

EXPOSE 80

CMD exec gunicorn --bind :80 --workers 1 --threads 8 --timeout 0 docker:app
