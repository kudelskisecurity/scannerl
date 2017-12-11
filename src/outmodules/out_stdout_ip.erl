%% output module - output only the ip of the target if fp successful

-module(out_stdout_ip).
-behavior(out_behavior).
-author("David Rossier - david.rossier@kudelskisecurity.com").

-export([init/2, clean/1, output/2]).
-export([get_description/0]).
-export([get_arguments/0]).

-define(ERR_ARG, "arg=[Output_file_path]").
-define(DESCRIPTION, "output to stdout (only IP)").
-define(ARGUMENTS, []).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% this is the initialization interface for this module
%% returns {ok, Obj} or {error, Reason}
init(_Scaninfo, []) ->
  {ok, []}.

%% this is the cleaning interface for this module
%% returns ok or {error, Reason}
clean(_Object) ->
  ok.

get_description() ->
  ?DESCRIPTION.

get_arguments() ->
  ?ARGUMENTS.

%% this is the output interface
%% output'ing to file
%% returns ok or {error, Reason}
output(_Obj, []) ->
  ok;
output(Obj, [H|T]) ->
  output_one(Obj, H),
  output(Obj, T).

output_one(_Object, {_Mod, {A,B,C,D}, _Port, {{ok,result},_Result}}) ->
  io:fwrite("~p.~p.~p.~p~n", [A,B,C,D]);
output_one(_Object, _Msg) ->
  ok.

