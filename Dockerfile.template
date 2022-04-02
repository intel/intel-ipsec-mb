# Build Stage
FROM ubuntu:20.04 as builder

## Install build dependencies.
RUN apt-get update && \
    apt-get install -y nasm && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y cmake clang

## Add source code to the build stage.
ADD . /intel-ipsec-mb
WORKDIR /intel-ipsec-mb

## TODO: ADD YOUR BUILD INSTRUCTIONS HERE. 
RUN make
RUN make install
WORKDIR /intel-ipsec-mb/test/
RUN make job_api_fuzz_test

# Package Stage
#FROM ubuntu:20.04

## TODO: Change <Path in Builder Stage>
#COPY --from=builder /intel-ipsec-mb/test/job_api_fuzz_test /

