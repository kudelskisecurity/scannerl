%% output module - output to file in CSV format

-module(out_csvfile).
-behavior(out_behavior).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-export([init/2, clean/1, output/2]).
-export([get_description/0]).
-export([get_arguments/0]).

-define(ERR_ARG, "arg=[saveall:Output_file_path]").
-define(SEP, ",").
-define(DESCRIPTION, "output to csv file").
-define(ARGUMENTS, ["[true|false] save everything [Default:false]", "File path"]).

-record(opt, {
    path,
    saveall,
    fd
  }).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% this is the initialization interface for this module
%% returns {ok, Obj} or {error, Reason}
init(_Scaninfo, [Saveall, Path]) ->
  case file:open(Path, [write, delayed_write, {encoding, utf8}]) of
    {ok, Fd} ->
      Opts = #opt{path=Path, saveall=list_to_atom(Saveall), fd=Fd},
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

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% output
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% convert to string
elem_to_string({_,_,_,_}=Ip) ->
  [inet_parse:ntoa(Ip)];
elem_to_string(Elem) when is_atom(Elem) ->
  atom_to_list(Elem);
elem_to_string(Elem) when is_tuple(Elem) ->
  tuple_to_list(Elem);
elem_to_string(Elem) when is_binary(Elem) ->
  binary_to_list(Elem);
elem_to_string(Elem) when is_float(Elem) ->
  float_to_list(Elem, [{decimals, 20}]);
elem_to_string(Elem) when is_integer(Elem) ->
  integer_to_list(Elem);
elem_to_string(Elem) when is_integer(Elem) ->
  integer_to_list(Elem);
elem_to_string(Elem) ->
  Elem.

% print line
output_elem(Fd, Elem) ->
  file:write(Fd, Elem ++ "\n").

% list to string
list_to_strings(List) ->
  case io_lib:printable_list(List) of
    true ->
      List;
    false ->
      Fixed = lists:map(fun elem_to_string/1, List),
      string:join(Fixed, ?SEP)
  end.

% list to CSV
handle_elem(Fd, List) ->
  Fixed = list_to_strings(List),
  output_elem(Fd, Fixed).

% handle list
handle_list(_Fd, []) ->
  ok;
handle_list(Fd, [H|T]) when is_list(H) ->
  handle_elem(Fd, H),
  handle_list(Fd, T);
handle_list(Fd, List) ->
  handle_elem(Fd, List).

% process result
handle_result(Fd, Res) when is_list(Res) ->
  handle_list(Fd, Res);
handle_result(Fd, Res) ->
  output_elem(Fd, elem_to_string(Res)).

% process error
handle_error(Fd, Tgt, State, Err) ->
  Fixed = list_to_strings(["ERROR", Tgt, State, Err]),
  output_elem(Fd, Fixed).

%% this is the output interface
%% returns ok or {error, Reason}
output(_Obj, []) ->
  ok;
output(Obj, [H|T]) ->
  output_one(Obj, H),
  output(Obj, T).

output_one(Obj, {_Mod, _Tgt, _Port, {{ok, result}, [Msg]}}) ->
  handle_result(Obj#opt.fd, Msg);
output_one(Obj, {_Mod, Tgt, _Port, {{error, State}, Err}}) when Obj#opt.saveall == true ->
  handle_error(Obj#opt.fd, Tgt, State, Err);
output_one(_Obj, _) ->
  ok.

