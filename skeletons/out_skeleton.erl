%% output module - TODO

%% rename this to the filename without the extension
-module(out_todo).
-behavior(out_behavior).
-author("TODO").

-export([init/2, clean/1, output/2]).
-export([get_description/0]).
-export([get_arguments/0]).

%% this is the error returned when wrong
%% arguments are provided
%% remove if no argument
-define(ERR_ARG, "TODO").
%% this is the description displayed when
%% listing the available modules
-define(DESCRIPTION, "TODO").
%% this is the list of arguments
%% as strings
-define(ARGUMENTS, []).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% this is the initialization interface for this module
%% returns {ok, Obj} or {error, Reason}
init(_Scaninfo, []) ->
  ok;
init(_Scaninfo, _) ->
  {error, ?ERR_ARG}.

%% this is the cleaning interface for this module
%% returns ok or {error, Reason}
clean(_Obj) ->
  ok.

get_description() ->
  ?DESCRIPTION.
get_arguments() ->
  ?ARGUMENTS.

%% this is the output interface
%% returns ok or {error, Reason}
output(_Obj, []) ->
  ok;
output(Obj, [H|T]) ->
  output_one(Obj, H),
  output(Obj, T).

output_one(_Obj, _Msg) ->
  ok.

