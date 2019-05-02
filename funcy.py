#!/usr/bin/python
# -*- coding: utf-8 -*-
import logging
import copy
log = logging.getLogger(__name__)
############################################
# promts user for yes or no
# returns 1 on yes
# returns 0 on no.
def yaynay():
    inp = ""
    while (inp != "y") and (inp != "n"):
        inp = raw_input('(y/n)>')
    if inp == "n":
        return 0
    if inp == "y":
        return 1

#############################################
# get payload list
# payloadfile str (path)
# returns list.
def get_payloads(payloadfile):
    try:
        payloads = open(payloadfile, "r").readlines()
        log.info("loading, \""+payloadfile+"\"")
        log.info(str(len(payloads))+" payloads in \""+payloadfile+"\"")
    except:
        log.critical("can't open \""+payloadfile+"\"")
        quit()
    return payloads

#############################################
# decode the payloads.
#  payloads list
#  returns list.
def decode_payloads(payloads):
    out = []
    i = 1
    for x in payloads:
        try:
            out.append(base64.b64decode(x))
        except:
            log.warning("Could not decode b64 payload on line "+str(i))
            if yaynay():
                pass
            else:
                quit()
        i+=1
    return out


#############################################
#  headers list of post_data.
#  returns dic.
def data_to_dic(data):
    out = {}
    for x in data:
        y = x.split('=')
        out[y[0]] = y[1]
    return out

#############################################
#  data dic, payload sting
#  returns dic.
def inject_payload(data ,payload):
    out = copy.deepcopy(data)
    for key in out:
        out[key] = data[key].replace('BECKY', payload)
    log.debug(out)
    return out
