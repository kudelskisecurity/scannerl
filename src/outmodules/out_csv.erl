%% output module - output in CSV format

-module(out_csv).
-behavior(out_behavior).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-export([init/2, clean/1, output/2, elem_to_string/1]).
-export([get_description/0]).
-export([get_arguments/0]).

-define(ERR_ARG, "arg=[saveall]").
-define(SEP, ",").
-define(DESCRIPTION, "output to csv").
-define(ARGUMENTS, ["[true|false] save everything [Default:true]"]).

-record(opt, {
    saveall
  }).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% this is the initialization interface for this module
%% returns {ok, Obj} or {error, Reason}
init(_Scaninfo, [Saveall]) ->
  {ok, #opt{saveall=list_to_atom(Saveall)}};
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

% print stderr
output_err(Elem) ->
  Val = io_lib:fwrite("~ts~n", [Elem]),
  io:put_chars(standard_error, Val).

% print stdout
output_elem(Elem) ->
  io:fwrite("~ts~n", [Elem]).

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
handle_elem(List) ->
  Fixed = list_to_strings(List),
  output_elem(Fixed).

% handle list
handle_list([]) ->
  ok;
handle_list([H|T]) when is_list(H) ->
  handle_elem(H),
  handle_list(T);
handle_list(List) ->
  handle_elem(List).

% process result
handle_result(Res) when is_list(Res) ->
  handle_list(Res);
handle_result(Res) ->
  output_elem(elem_to_string(Res)).

% process error
handle_error(Tgt, State, Err) ->
  Fixed = list_to_strings(["ERROR", Tgt, State, Err]),
  output_err(Fixed).

%% this is the output interface
%% output'ing to stdout
%% returns ok or {error, Reason}
output(_Obj, []) ->
  ok;
output(Obj, [H|T]) ->
  output_one(Obj, H),
  output(Obj, T).

output_one(_Obj, {_Mod, _Tgt, _Port, {{ok, result}, [Msg]}}) ->
  handle_result(Msg);
output_one(Obj, {_Mod, Tgt, _Port, {{error, State}, Err}}) when Obj#opt.saveall == true ->
  handle_error(Tgt, State, Err);
output_one(_Obj, _) ->
  ok.

