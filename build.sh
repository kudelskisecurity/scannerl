#!/bin/sh
# https://github.com/kudelskisecurity/scannerl
version="0.39"

# check deps
hash erl 2>/dev/null || { echo "install \"erlang\" (https://github.com/kudelskisecurity/scannerl)"; exit 1; }
hash rebar 2>/dev/null || { echo "install \"rebar\" (https://github.com/kudelskisecurity/scannerl)"; exit 1; }

# check erlang version
erlversion=`erl -eval 'erlang:display(list_to_integer(erlang:system_info(otp_release))), halt().'  -noshell \
  | tr -d '\r'`
[ "${erlversion}" -lt "18" ] && echo "Your erlang version is too old, you should update it" && exit 1

# Updating fpmodules list
for i in `ls -1 ./src/fpmodules -I fp_module.erl`; do
  echo ${i%.*erl} | sed 's/^fp_//g'
done | tr '\n' ',' | \
       sed 's/^/\-define(FP_MODULES_LIST, [/' | \
       sed 's/,$/])./' > ./src/includes/fpmodules.hrl

# Updating outmodules list
for i in `ls -1 ./src/outmodules -I out_behavior.erl`; do
  echo ${i%.*erl} | sed 's/^out_//g'
done | tr '\n' ',' | \
       sed 's/^/\-define(OUT_MODULES_LIST, [/' | \
       sed 's/,$/])./' > ./src/includes/outmodules.hrl

# update git hash
gitv=`git rev-parse --short HEAD 2>/dev/null`
echo "-define(VERSION, \"${version}\")." > ./src/includes/defines.hrl
echo "-define(GIT_SHORT_HASH, \"${gitv}\")." >> ./src/includes/defines.hrl 2>/dev/null
echo "-define(ERLANG_VERSION, \"${erlversion}\")." >> ./src/includes/defines.hrl
[ "${erlversion}" -lt "20" ] && echo "-define(USE_GENFSM, true)." >> ./src/includes/defines.hrl
echo "-define(ARGSHDR, \"`cat ./src/includes/args.hrl`\")." >> ./src/includes/defines.hrl

# Compile
rebar compile escriptize
