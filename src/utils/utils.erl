%% utils

-module(utils).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-export([get_ts/0, scaninfo_print/1]).
-export([debug_parse/1, debug_print/2, debug/4]).
-export([outputs_init/2, outputs_clean/1, outputs_send/2]).
-export([read_lines/1]).

-include("../includes/opts.hrl").

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% output
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
outputs_init(Outs, Scaninfo) ->
  output_init(Outs, Scaninfo, []).

outputs_clean(Outs) ->
  output_clean(Outs).

outputs_send(Outs, Msg) ->
  output_send(Outs, Msg).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% output utils
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% send message to output modules
output_send([], _) ->
  ok;
output_send([{Mod, _Args, Obj}|T], Msg) ->
  apply(Mod, output, [Obj, Msg]),
  output_send(T, Msg).

% init output modules
% returns either
%   {ok, Acc}: a list of tuple in the form {Out, [Args], Out-Object}
%   {error, Reason}
output_init([], _, Acc) ->
  {ok, Acc};
output_init([{Mod, Args}|T], Scaninfo, Acc) ->
  % init the module
  try apply(Mod, init, [Scaninfo, Args]) of
    {ok, Obj} ->
      output_init(T, Scaninfo, [{Mod, Args, Obj}|Acc]);
    {error, Reason} ->
      output_clean(Acc),
      {error, Reason}
  catch
    _:_ ->
      utils_opts:print(io_lib:fwrite("[ERROR] output module ~p does not exist", [Mod])),
      utils_opts:usage()
  end.

% clean output modules
output_clean([]) ->
  ok;
output_clean([{Mod, _Args, Obj}|T]) ->
  case apply(Mod, clean, [Obj]) of
    ok ->
      output_clean(T);
    {error, _Reason} ->
      output_clean(T)
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% utils
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% get current timestamp
get_ts() ->
  Now = calendar:local_time(),
  {{Y,M,D}, {H,Min,S}} = Now,
  io_lib:fwrite("~w~2..0w~2..0w~2..0w~2..0w~2..0w", [Y, M, D, H, Min, S]).

scaninfo_print(Scaninfo) ->
  Dbgval = Scaninfo#scaninfo.debugval,
  utils:debug(scannerl, "", {}, Dbgval),
  utils:debug(scannerl, "-------- scaninfo -------", {}, Dbgval),
  utils:debug(scannerl, io_lib:fwrite("Version:  ~p",
    [Scaninfo#scaninfo.version]), {}, Dbgval),
  utils:debug(scannerl, io_lib:fwrite("Module:   ~p",
    [Scaninfo#scaninfo.fpmodule]), {}, Dbgval),
  utils:debug(scannerl, io_lib:fwrite("Port:     ~p",
    [Scaninfo#scaninfo.port]), {}, Dbgval),
  utils:debug(scannerl, io_lib:fwrite("Debug:    ~p",
    [Scaninfo#scaninfo.debugval]), {}, Dbgval),
  utils:debug(scannerl, "-------------------------", {}, Dbgval),
  utils:debug(scannerl, "", {}, Dbgval).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% debug
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
debug_parse(Value) when Value == 0 ->
  #debugval{
    value=Value,
    level1=false,
    level2=false,
    level4=false,
    level8=false,
    level16=false,
    level32=false,
    level64=false,
    level128=false
  };
debug_parse("true") ->
  debug_inner_parse(binary:encode_unsigned(255));
debug_parse(Value) ->
  % let's just hope the user doesn't do "-v abc"
  debug_inner_parse(binary:encode_unsigned(list_to_integer(Value))).

debug_inner_parse(<<
    L128:1,
    L64:1,
    L32:1,
    L16:1,
    L8:1,
    L4:1,
    L2:1,
    L1:1
  >> = Value) ->
  case L16 == 1 orelse L128 == 1 of
    true ->
      io:fwrite("[DBG] [~s] [scannerl] level-1   (fpmodules):    ~p~n", [get_ts(), L1==1]),
      io:fwrite("[DBG] [~s] [scannerl] level-2   (outmodules):   ~p~n", [get_ts(), L2==1]),
      io:fwrite("[DBG] [~s] [scannerl] level-4   (broker):       ~p~n", [get_ts(), L4==1]),
      io:fwrite("[DBG] [~s] [scannerl] level-8   (master):       ~p~n", [get_ts(), L8==1]),
      io:fwrite("[DBG] [~s] [scannerl] level-16  (scannerl):     ~p~n", [get_ts(), L16==1]),
      io:fwrite("[DBG] [~s] [scannerl] level-32  (?):            ~p~n", [get_ts(), L32==1]),
      io:fwrite("[DBG] [~s] [scannerl] level-64  (?):            ~p~n", [get_ts(), L64==1]),
      io:fwrite("[DBG] [~s] [scannerl] level-128 (additional):   ~p~n", [get_ts(), L128==1]);
    false ->
      ok
  end,
  [Val|[]] = binary_to_list(Value),
  #debugval{
    value=Val,
    level1=L1==1,
    level2=L2==1,
    level4=L4==1,
    level8=L8==1,
    level16=L16==1,
    level32=L32==1,
    level64=L64==1,
    level128=L128==1
  }.

debug_more_info(Debugval, Msg) when Debugval#debugval.level128 ->
  {_, Cnt} = erlang:process_info(self(), message_queue_len),
  %erlang:memory()
  io_lib:fwrite("[ql:~p] ~s", [Cnt, Msg]);
debug_more_info(_, Msg) ->
  Msg.

% for master.erl and scannerl
% expects an atom in From
debug_print(From, Msg) ->
  Out = io_lib:fwrite("[DBG] [~s] [~s] ~s\n", [get_ts(), atom_to_list(From), Msg]),
  io:put_chars(standard_error, Out).

debug(fpmodules, Msg, {Tgt, Id}, Dbg) when Dbg#debugval.level1 ->
  % from fpmodules to master
  Pid = global:whereis_name(master),
  Msg2 = io_lib:fwrite("[~s|~p]: ~s", [Id, Tgt, Msg]),
  Pid ! {debug, fpmodules, debug_more_info(Dbg, Msg2)};
debug(outmodules, Msg, _, Dbg) when Dbg#debugval.level2->
  % from outmodules to master
  Pid = global:whereis_name(master),
  Pid ! {debug, outmodules, debug_more_info(Dbg, Msg)};
debug(broker, Msg, {Id}, Dbg) when Dbg#debugval.level4 ->
  % from broker to master
  Pid = global:whereis_name(master),
  Msg2 = io_lib:fwrite("[~s]: ~s", [Id, Msg]),
  Pid ! {debug, broker, debug_more_info(Dbg, Msg2)};
debug(master, Msg, _, Dbg) when Dbg#debugval.level8 ->
  % master to stderr
  debug_print(master, debug_more_info(Dbg, Msg));
debug(scannerl, Msg, _, Dbg) when Dbg#debugval.level16 ->
  % from scannerl to stderr
  debug_print(scannerl, debug_more_info(Dbg, Msg));
debug(_, _, _, _) ->
  ok.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% file reading
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
validate_line([]) ->
  nil;
validate_line("#" ++ _) ->
  nil;
validate_line("%" ++ _) ->
  nil;
validate_line(Line) ->
  Line.

% string to list of line (separator is \n)
list_to_lines("\n" ++ [], Acc) ->
  case validate_line(lists:reverse(Acc)) of
    nil -> [];
    Val -> [Val]
  end;
list_to_lines("\n" ++ Rest, Acc) ->
  case validate_line(lists:reverse(Acc)) of
    nil -> list_to_lines(Rest, []);
    Val -> [Val |  list_to_lines(Rest, [])]
  end;
list_to_lines([H|T], Acc) ->
  list_to_lines(T, [H|Acc]);
list_to_lines([], Acc) ->
  case validate_line(lists:reverse(Acc)) of
    nil -> [];
    Val -> [Val]
  end.

read_lines(Path) ->
  case file:read_file(Path) of
    {ok, Bin} ->
      Lines = list_to_lines(binary_to_list(Bin), []),
      {ok, Lines};
   {error, Reason} ->
      {error, Reason}
  end.

