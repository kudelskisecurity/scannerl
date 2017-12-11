%%% MQTT fingerprinting module
%%%
%%% Output:
%%%   mqtt or not_mqtt atoms
%%%

-module(fp_mqtt).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-behavior(fp_module).

-include("../includes/args.hrl").

-export([callback_next_step/1]).
-export([get_default_args/0]).
-export([get_description/0]).
-export([get_arguments/0]).

%% our record for this fingerprint
-define(TIMEOUT, 3000). % milli-seconds
-define(PORT, 1883). % HTTP port
-define(TYPE, tcp). % transport type
-define(MAXPKT, 1). % max packet expected
-define(DESCRIPTION, "TCP/1883: MQTT identification").
-define(ARGUMENTS, []).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% public API to get {port, timeout}
get_default_args() ->
  #args{module=?MODULE, type=?TYPE, port=?PORT,
    timeout=?TIMEOUT, maxpkt=?MAXPKT}.

get_description() ->
  ?DESCRIPTION.

get_arguments() ->
  ?ARGUMENTS.

% callback
callback_next_step(Args) when Args#args.moddata == undefined ->
  % first packet
  debug(Args, "first packet"),
  {continue, Args#args.maxpkt, get_payload(), true};
callback_next_step(Args) when Args#args.packetrcv < 1 ->
  % no packet received
  debug(Args, "no packet received"),
  {result, {{error, up}, timeout}};
callback_next_step(Args) ->
  debug(Args, "a packet received"),
  {result, parse_payload(Args#args.datarcv)}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% debug
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% send debug
debug(Args, Msg) ->
  utils:debug(fpmodules, Msg,
    {Args#args.target, Args#args.id}, Args#args.debugval).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% utils
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
get_payload() ->
  utils_mqtt:forge_connect().

parse_payload(Pkt) ->
  {Val, _Res} = utils_mqtt:parse(Pkt),
  case Val of
    false ->
      {{error, up}, not_mqtt};
    true ->
      {{ok, result}, mqtt}
  end.

