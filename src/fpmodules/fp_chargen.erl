%%% Chargen fingerprinting module
%%%
%%% Output:
%%% {{ok,result}, [chargen, {amplification_factor, Factor}]}
%%%

-module(fp_chargen).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").
-author("David Rossier - david.rossier@kudelskisecurity.com").
-behavior(fp_module).

-include("../includes/args.hrl").

-export([get_default_args/0]).
-export([callback_next_step/1]).
-export([get_description/0]).
-export([get_arguments/0]).

-define(TIMEOUT, 3000). % milli-seconds
-define(PORT, 19). % chargen port
-define(TYPE, udp). % transport type
-define(MAXPKT, 1). %  max packet expected

% chargen will discard the data anyway
% but for the sake of the amplification calculation
% and since the minimum payload of UDP is 18 bytes
% here are some bytes
-define(CHARGENDATA, [
    16#0a,16#0a,16#0a,16#0a,
    16#0a,16#0a,16#0a,16#0a,
    16#0a,16#0a,16#0a,16#0a,
    16#0a,16#0a,16#0a,16#0a,
    16#0a,16#0a
  ]).
-define(QUERYSZ, length(?CHARGENDATA)).

-define(DESCRIPTION, "UDP/19: Chargen amplification factor identification").
-define(ARGUMENTS, []).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% public API to get {port, timeout}
get_default_args() ->
  #args{module=?MODULE, type=udp, port=?PORT,
    timeout=?TIMEOUT, maxpkt=?MAXPKT}.

get_description() ->
  ?DESCRIPTION.

get_arguments() ->
  ?ARGUMENTS.

callback_next_step(Args) when Args#args.moddata == undefined ->
  {continue, Args#args.maxpkt, ?CHARGENDATA, true};
callback_next_step(Args) when Args#args.packetrcv < 1 ->
  {result, {{error,unknown}, timeout}};
callback_next_step(Args) ->
  Amp = byte_size(Args#args.datarcv) / ?QUERYSZ,
  Res = [chargen, {amplification_factor, Amp}],
  {result, {{ok, result}, Res}}.

