%% output module - output to stdout

-module(out_stdout).
-behavior(out_behavior).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-export([init/2, clean/1, output/2]).
-export([get_description/0]).
-export([get_arguments/0]).

-define(DESCRIPTION, "output to stdout").
-define(ARGUMENTS, []).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% this is the initialization interface for this module
%% returns {ok, Obj} or {error, Reason}
init(_Scaninfo, _Options) ->
  {ok, []}.

%% this is the cleaning interface for this module
%% returns ok or {error, Reason}
clean(_Obj) ->
  ok.

get_description() ->
  ?DESCRIPTION.

get_arguments() ->
  ?ARGUMENTS.

%% this is the output interface
%% output'ing to stdout
%% returns ok or {error, Reason}
output(_Obj, []) ->
  ok;
output(Obj, [H|T]) ->
  output_one(Obj, H),
  output(Obj, T).

output_one(_Obj, Msg) ->
  io:fwrite("Result: ~10000tp~n", [Msg]).


