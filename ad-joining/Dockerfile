
FROM gcc:latest as build-cc
ADD /ksetpwd /ksetpwd
RUN cd /ksetpwd && make ksetpwd

FROM python:3.7 as build-python
ADD /register-computer /register-computer
RUN pip3 install -r /register-computer/requirements.txt --no-cache-dir -t /site-packages

FROM gcr.io/distroless/python3-debian10
COPY --from=build-python /register-computer /register-computer
COPY --from=build-python /site-packages /site-packages
COPY --from=build-cc /ksetpwd /register-computer/kerberos/bin
COPY --from=build-cc /lib/x86_64-linux-gnu/libcom_err.* /register-computer/kerberos/bin/

ENV PYTHONPATH=/site-packages

EXPOSE 80

ENTRYPOINT [ "python3", "/register-computer/main.py" ]
