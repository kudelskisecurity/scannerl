%%% TODO fingerprint module
%%%
%%% Output:
%%% TODO
%%%

-module(fp_todo).
-author("TODO").

-behavior(fp_module).
-include("../includes/args.hrl").

-export([callback_next_step/1]).
-export([get_default_args/0]).
-export([get_description/0]).
-export([get_arguments/0]).

-define(TIMEOUT, 3000). % milli-seconds
-define(PORT, 123). % TODO
-define(TYPE, tcp). % transport type
-define(MAXPKT, 2). % TODO
-define(DESCRIPTION, "TCP/TODO: TODO").
-define(ARGUMENTS, []).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
get_default_args() ->
  #args{module=?MODULE, type=?TYPE, port=?PORT,
    timeout=?TIMEOUT, maxpkt=?MAXPKT}.

get_description() ->
  ?DESCRIPTION.

get_arguments() ->
  ?ARGUMENTS.

callback_next_step(Args) when Args#args.moddata == undefined ->
  % TODO
  {continue, Args#args.maxpkt, "TODO", true};
callback_next_step(Args) when Args#args.packetrcv < 1 ->
  {result, {{error,up}, timeout}};
callback_next_step(Args) ->
  % TODO parse
  {result, {ok, result}, ok}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% debug
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% send debug
debug(Args, Msg) ->
  utils:debug(fpmodules, Msg,
    {Args#args.target, Args#args.id}, Args#args.debugval).

