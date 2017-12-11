%%% FOX fingerprinting module
%%%
%%% Output:
%%%   true (is fox) or false (isn't fox)
%%%

-module(fp_fox).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-behavior(fp_module).

-include("../includes/args.hrl").

-export([callback_next_step/1]).
-export([get_default_args/0]).
-export([get_description/0]).
-export([get_arguments/0]).

%% our record for this fingerprint
-define(TIMEOUT, 3000). % milli-seconds
-define(PORT, 1911). % port
-define(TYPE, tcp). % transport type
-define(MAXPKT, 50). % max packet expected
-define(DESCRIPTION, "TCP/1911: FOX identification").
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
  utils_fox:forge_min_hello().

parse_payload(<< >>) ->
  {{error, up}, not_fox};
parse_payload(Pkt) ->
  Ret = utils_fox:parse_full(binary_to_list(Pkt)),
  case Ret of
    {false, Proto} ->
      {{error, up}, Proto};
    {false} ->
      {{error, up}, not_fox};
    {true, Stuff} ->
      {{ok, result}, Stuff}
  end.

