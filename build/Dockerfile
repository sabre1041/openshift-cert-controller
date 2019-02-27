FROM alpine:3.8

ENV OPERATOR=/usr/local/bin/openshift-cert-controller \
    USER_UID=1001 \
    USER_NAME=openshift-cert-controller

# install operator binary
COPY build/_output/bin/openshift-cert-controller ${OPERATOR}

COPY build/bin /usr/local/bin
RUN  /usr/local/bin/user_setup

ENTRYPOINT ["/usr/local/bin/entrypoint"]

USER ${USER_UID}
