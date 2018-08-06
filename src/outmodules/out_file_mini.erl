%% output module - output only the ip and the result to a file

-module(out_file_mini).
-behavior(out_behavior).
-author("David Rossier - david.rossier@kudelskisecurity.com").
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-export([init/2, clean/1, output/2]).
-export([get_description/0]).
-export([get_arguments/0]).

-define(ERR_ARG, "arg=[Output_file_path]").
-define(DESCRIPTION, "output to file (only ip and result)").
-define(ARGUMENTS, ["File path"]).

-record(opt, {path, fd}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% this is the initialization interface for this module
%% returns {ok, Obj} or {error, Reason}
init(_Scaninfo, [Path]) ->
  case file:open(Path, [write, delayed_write, {encoding, utf8}]) of
    {ok, Fd} ->
      Opts = #opt{path=Path, fd=Fd},
      {ok, Opts};
    {error, Reason} ->
      {error, Reason}
  end;
init(_Scaninfo, _) ->
  {error, ?ERR_ARG}.

%% this is the cleaning interface for this module
%% returns ok or {error, Reason}
clean(Object) ->
  file:close(Object#opt.fd).

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

output_one(Object, {_Module, Target, _Port, Result}) ->
  Out = io_lib:fwrite("~p,~999999tp~n", [Target, Result]),
  file:write(Object#opt.fd, Out).
