#!/usr/bin/env bash
#By h46incon, wuweixing

#Dependences: curl, openssl-util, tr, sort
#env: MY_ALIYUN_KEY, MY_ALIYUN_SECRET, DOMAIN, DomainRR

## ----- Log level -----
_DEBUG_=false
_LOG_=true
_ERR_=true

## ----- Setting -----
AccessKeyId=${MY_ALIYUN_KEY}
AccessKeySec=${MY_ALIYUN_SECRET}

# DomainRR, use "@" to set top level domain
DomainRR=${1:-${DomainRR}}
DomainName=${DOMAIN}
DomainType=${DOMAIN_TYPE:-A}
DomainRecordId=""

# The server address of ALi API
ALiServerAddr="alidns.aliyuncs.com"
# A url provided by a third-party to echo the public IP of host
MyIPEchoUrl="http://whatismyip.akamai.com/"

if [ "${DomainType}" == "AAAA" ]; then
  MyIPEchoUrl="http://ipv6.whatismyip.akamai.com/"
fi

## ===== private =====

## ----- global var -----
# g_pkey_$i    # param keys
# g_pval_$key  # param values
g_pn=0         # number of params
_func_ret=""


## ----- Base Util -----
_debug()	{ ${_DEBUG_} && echo $(date "+%F %T") "DEBUG $*"; }
_log() 		{ ${_LOG_}   && echo $(date "+%F %T") "INFO $*"; }
_err() 		{ ${_ERR_}   && echo $(date "+%F %T") "ERROR $*" >&2; }

reset_func_ret() {
  _func_ret=""
}

## ----- params -----
# @Param1: Key
# @Param2: Value
put_param() {
  eval g_pkey_${g_pn}=$1
  eval g_pval_$1=$2
  g_pn=$((g_pn + 1))
}

reset_param() {
  g_pn=0
}

# This function will init all public params EXCLUDE "Signature"
put_params_public() {
  put_param "Format" "JSON"
  put_param "Version" "2015-01-09"
  put_param "AccessKeyId" "${AccessKeyId}"
  put_param "SignatureMethod" "HMAC-SHA1"
  put_param "SignatureVersion" "1.0"
  rand_num=$(openssl rand -hex 16)

  # time stamp
  local time_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  _debug time_stamp: ${time_utc}
  put_param "Timestamp" "${time_utc}"

  # random number
  _debug rand_num: ${rand_num}
  put_param "SignatureNonce" "${rand_num}"
}

# @Param1: New IP address
put_params_UpdateDomainRecord() {
  put_param "Action" "UpdateDomainRecord"
  put_param "RR" "${DomainRR}"
  put_param "RecordId" "${DomainRecordId}"
  put_param "Type" "${DomainType}"
  put_param "Value" "${1}"
}

put_params_DescribeDomainRecordInfo() {
  put_param "Action" "DescribeDomainRecords"
  put_param "DomainName" "${DomainName}"
  put_param "RRKeyWord" "${DomainRR}"
  put_param "Type" "${DomainType}"
}

pack_params() {
  reset_func_ret
  local ret=""
  local key key_enc val val_enc

  local i=0
  while [ $i -lt ${g_pn} ]; do
    eval key="\$g_pkey_${i}"
    eval val="\$g_pval_${key}"
    rawurl_encode "${key}"
    key_enc=${_func_ret}
    rawurl_encode "${val}"
    val_enc=${_func_ret}

    ret="${ret}${key_enc}=${val_enc}&"
    i=$((++i))
  done

  #delete last "&"
  _func_ret=${ret%"&"}
}


# ----- Other utils -----

get_my_ip() {
  reset_func_ret
  local my_ip=$(curl ${MyIPEchoUrl} --silent --connect-timeout 10)
  # local my_ip=$(ipconfig getifaddr en0)
  # local my_ip=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1')

  #echo ${my_ip}
  _func_ret=${my_ip}
}

get_domain_ip() {
  put_params_public
  put_params_DescribeDomainRecordInfo
  send_request
  local result=${_func_ret}
  reset_param
  reset_func_ret

  _func_ret=$(echo ${result} |grep -Eo '"Value":"[0-9a-f:.]+"' |grep -Eo '[0-9a-f:.]{5,}')
  DomainRecordId=$(echo ${result} |grep -Eo '"RecordId":"[0-9]+"' |grep -Eo '[0-9]{5,}')
  if [ -z ${DomainRecordId} ]; then
    _err get domain ip failed ${result}
    exit 1
  fi
  _debug DomainRecordId: ${DomainRecordId}
}

# @Param1: Raw url to be encoded
rawurl_encode() {
  reset_func_ret

  local string="${1}"
  local strlen=${#string}
  local encoded=""
  local pos c o

  pos=0
  while [ ${pos} -lt ${strlen} ]; do
    c=${string:$pos:1}
    case "$c" in
      [-_.~a-zA-Z0-9] ) o="${c}" ;;
      * ) o=$(printf "%%%02X" "'$c") ;;
    esac
    encoded="${encoded}${o}"
    pos=$(($pos + 1))
  done
  _func_ret="${encoded}"
}

calc_signature() {
  reset_func_ret

  local sorted_key=$(
    i=0
    while [ $i -lt ${g_pn} ]; do
      eval key="\$g_pkey_$i"
      echo "${key}"
      i=$((++i))
    done | LC_ALL=C sort
  )

  local query_str=""

  for key in ${sorted_key}; do
    eval val="\$g_pval_${key}"

    rawurl_encode "${key}"
    key_enc=${_func_ret}
    rawurl_encode "${val}"
    val_enc=${_func_ret}

    query_str="${query_str}${key_enc}=${val_enc}&"
  done

  # delete last "&"
  query_str=${query_str%"&"}

  _debug Query String: ${query_str}
  # encode
  rawurl_encode "${query_str}"
  local encoded_str=${_func_ret}
  local str_to_signed="GET&%2F&"${encoded_str}
  _debug String to Signed: ${str_to_signed}

  local key_sign="${AccessKeySec}&"
  _func_ret=$(/bin/echo -n ${str_to_signed} | openssl dgst -binary -sha1 -hmac ${key_sign} | openssl enc -base64)
}

send_request() {
  reset_func_ret
  # put signature
  calc_signature
  local signature=${_func_ret}
  put_param "Signature" "${signature}"

  # pack all params
  pack_params
  local packed_params=${_func_ret}

  local req_url="${ALiServerAddr}/?${packed_params}"
  _debug Request addr: ${req_url}

  local respond=$(curl -3 ${req_url} --silent --connect-timeout 10 -w "HttpCode:%{http_code}")
  _debug ${respond}
  _func_ret=${respond}
}

update_record() {
  get_my_ip
  local my_ip=${_func_ret}

  # Check if need update
  _debug My IP: ${my_ip}
  if [ -z "${my_ip}" ]; then
    _err Could not get my ip, exitting...
    exit
  fi

  get_domain_ip
  local domain_ip=${_func_ret}
  _debug Current Domain IP: ${domain_ip}

  if [ "${my_ip}" == "${domain_ip}" ]; then
    _log Need not to update, current IP: ${my_ip}
  else
    put_params_public
    put_params_UpdateDomainRecord ${my_ip}

    send_request
    _log updated ${my_ip}
  fi
}

_log ${DomainRR}.${DomainName} ${DomainType}
_debug AccessKeyId: ${AccessKeyId}
_debug AccessKeySec: ${AccessKeySec}
update_record
