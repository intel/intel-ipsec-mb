# Intel(R) Multi-Buffer Crypto for IPsec Library - Basic Sample Application

## Contents

- Overview
- Usage


## Overview

The basic sample application showcases how to authenticate 
several buffers with SHA1/224/256/384/512 using the single buffer API,
with all steps required, minimizing the number of lines of code needed,
so it can serve as a skeleton app for developers to start building their application.
The multi buffer and burst APIs are more performant. However, the use of 
single buffer SHA API's is sometimes preferred/required and
this app demonstrates how to use them.

## Usage

Usage:
    `./imb-single-buff SHAx`
