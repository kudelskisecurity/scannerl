%#!/usr/bin/env escript
%%! -smp enable -sname scannerl -K true -P 134217727 -kernel dist_nodelay false
%
% distributed fingerprinting engine
%
% Be aware that:
%   - hostnames must resolve (on each side)
%   - SSH is used to connect to slave nodes
%     - master username is used
%     - key authentication must be working
%     - remote must be trusted (ECDSA key)
%

-module(scannerl).
-export([main/1]).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").
-include("includes/opts.hrl").
-include("includes/args.hrl").
-include("includes/defines.hrl").

-ifdef(USE_GENFSM).
  -define(TCPFSM, fsm_tcp).
  -define(UDPFSM, fsm_udp).
  -define(SSLFSM, fsm_ssl).
  -define(FSMMODE, "using genfsm").
-else.
  -define(TCPFSM, statem_tcp).
  -define(UDPFSM, statem_udp).
  -define(SSLFSM, statem_ssl).
  -define(FSMMODE, "using statem").
-endif.

-define(MODULES, % master module
  [
    master,                % the master module
    utils,                 % utils
    utils_slave,           % utils to start slave nodes
    cntlist                % count list for slave nodes
  ]).
-define(SLMODULES, % slave modules
  [
    % base modules
    broker,               % the slave broker
    scannerl_worker_sup,  % the supervisor
    tgt,                  % the target parser/handler
    utils,                % utils
    utils_fp,             % fingerprinting utils
    fp_module,
    out_behavior,
    ?TCPFSM,
    ?UDPFSM,
    ?SSLFSM,
    % utilities
    utils_http,
    utils_ssl,
    utils_fox,
    utils_mqtt
  ]).
-define(SCANNERL, "scannerl").
-define(CHECKTO, 60000). % 1 minute

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% utilities
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
msg_queue_len() ->
  {_, Cnt} = erlang:process_info(self(), message_queue_len),
  Cnt.

% globally register myself as scannerl
register_myself() ->
  yes = global:register_name(list_to_atom(?SCANNERL), self()),
  yes = global:re_register_name(list_to_atom(?SCANNERL), self()),
  global:sync().

% print duration
duration(Start) ->
  Duration = calendar:datetime_to_gregorian_seconds(calendar:universal_time()) - Start,
  DateTime = calendar:gregorian_seconds_to_datetime(Duration),
  {{_Year, _Month, _Day}, {Hour, Min, Sec}} = DateTime,
  [Hour, Min, Sec].

print(error, Msg) ->
  M = io_lib:fwrite("> ~s\n", [Msg]),
  io:put_chars(standard_error, M);
print(stdout, Msg) ->
  M = io_lib:fwrite("> ~s\n", [Msg]),
  io:fwrite(M);
print(normal, Msg) ->
  M = io_lib:fwrite("~s\n", [Msg]),
  io:put_chars(standard_error, M).

progress(true, Nb, 0) ->
  M = io_lib:fwrite("[progress] ~p match on ? fingerprinted so far (queue_len: ~p)\n",
    [Nb, msg_queue_len()]),
  io:put_chars(standard_error, M);
progress(true, Nb, Tot) ->
  M = io_lib:fwrite("[progress] ~p match on ~p fingerprinted (~.2f%) so far (queue_len: ~p)\n",
    [Nb, Tot, Nb*100/Tot, msg_queue_len()]),
  io:put_chars(standard_error, M);
progress(false, _, _) ->
  ok.

% print the number of results and a percentage if possible
print_percentage(Cnt, 0) ->
  print(normal, io_lib:fwrite("nb result: ~p/~p", [Cnt, 0]));
print_percentage(Cnt, Tot) ->
  print(normal, io_lib:fwrite("nb result: ~p/~p (~.2f%)", [Cnt, Tot, Cnt*100/Tot])).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% output modules
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
outs_init(Outs, Scaninfo, Outmode) when Outmode == 0 ->
  %print(normal, "init output module(s)"),
  case utils:outputs_init(Outs, Scaninfo) of
    {error, Reason} ->
      print(error, io_lib:fwrite("Output setup failed: ~p", [Reason])),
      utils_opts:usage();
    {ok, Os} ->
      Os
  end;
outs_init(_, _, _) ->
  print(normal, "output is not done on master"),
  [].

outs_clean(_, Outmode) when Outmode /= 0 ->
  ok;
outs_clean(Outs, _) ->
  utils:outputs_clean(Outs).

outs_send(_, _, Outmode) when Outmode /= 0 ->
  ok;
outs_send(Outs, Msg, _) ->
  utils:outputs_send(Outs, [Msg]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% communication
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% check the queue for queuemax
check_queue(Opts) when Opts#opts.queuemax == 0 ->
  false;
check_queue(Opts) when Opts#opts.pause == true ->
  Nb = msg_queue_len(),
  case Nb < Opts#opts.queuemax/2 of
    true ->
      % we need to resume
      utils:debug(scannerl, io_lib:fwrite("requiring master to resume ~p/~p~n",
        [Nb, Opts#opts.queuemax]), {}, Opts#opts.debugval),
      erlang:garbage_collect(),
      try
        erlang:whereis(masternode) ! {resume}
      catch
        _:_ ->
          ok
      end,
      false;
    false ->
      true
  end;
check_queue(Opts) when Opts#opts.pause == false ->
  Nb = msg_queue_len(),
  case Nb > Opts#opts.queuemax of
    true ->
      % we need to pause
      utils:debug(scannerl, io_lib:fwrite("requiring master to pause ~p/~p~n",
        [Nb, Opts#opts.queuemax]), {}, Opts#opts.debugval),
      try
        erlang:whereis(masternode) ! {pause}
      catch
        _:_ ->
          ok
      end,
      true;
    false ->
      false
  end.

% returns either
%   error: error occured
%   {total done, nb positiv result, nb nodes}
rcv_loop(Opts, Outputs, Tot, Nbposres) ->
  Pause = check_queue(Opts),
  utils:debug(scannerl,
    io_lib:fwrite("(pause:~p) result received: ~p | queuelen: ~p", [Pause,
      Tot, msg_queue_len()]), {}, Opts#opts.debugval),
  receive
    {progress} ->
      % triggered by message server and sent by the master
      progress(true, Nbposres, Tot),
      rcv_loop(Opts, Outputs, Tot, Nbposres);
    {done, error} ->
      % sent by master
      {error};
    {done, {Nbnodes}} ->
      % sent by master
      {Tot, Nbposres, Nbnodes};
    Result = {_, _, _, {{ok, result}, _}} ->
      % sent by fp module
      outs_send(Outputs, Result, Opts#opts.outmode),
      progress(Opts#opts.progress, Nbposres, Tot),
      rcv_loop(Opts#opts{pause=Pause}, Outputs, Tot+1, Nbposres+1);
    Result = {_, _, _, {{_, _}, _}} ->
      % sent by fp module
      outs_send(Outputs, Result, Opts#opts.outmode),
      progress(Opts#opts.progress, Nbposres, Tot),
      rcv_loop(Opts#opts{pause=Pause}, Outputs, Tot+1, Nbposres);
    Msg ->
      % ?
      print(error, io_lib:fwrite("discarded message: ~p", [Msg])),
      rcv_loop(Opts#opts{pause=Pause}, Outputs, Tot, Nbposres)
  after
    ?CHECKTO ->
      rcv_loop(Opts#opts{pause=Pause}, Outputs, Tot, Nbposres)
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% master related
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% launch the scanning process
doit(Opts) ->
  Pid = spawn_link(master, master, [Opts]),
  erlang:register(masternode, Pid).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% entry point
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% end of scan
finishit(Start, _Outputs, _Outmode, {error}) ->
  print(normal, "Failed"),
  print(normal, io_lib:fwrite("duration: ~2..0w:~2..0w:~2..0w", duration(Start))),
  halt(1);
finishit(Start, Outputs, Outmode, {Cnt, Rescnt, _Nbslaves}) ->
  % clean outputs
  outs_clean(Outputs, Outmode),
  print_percentage(Rescnt, Cnt),
  print(normal, io_lib:fwrite("duration: ~2..0w:~2..0w:~2..0w", duration(Start))),
  halt(0).

% entry point
main(Args) ->
  _ = os:cmd("epmd -daemon"),
  Start = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
  register_myself(),

  % parsing the argument in a map
  %print(normal, "parsing args ..."),
  Map = utils_opts:getopt(Args),

  % print the banner
  utils_opts:banner(),

  % compile needed modules
  Tmp = ?SLMODULES ++ [maps:get("m", Map)],
  Omods = lists:filtermap(fun(X) -> {M, _} = X, {true, M} end, maps:get("o", Map)),
  Mods = lists:append([Tmp, Omods]),

  % print erlang version
  print(normal, io_lib:fwrite("compiled with erlang ~s (~s)", [?ERLANG_VERSION, ?FSMMODE])),

  % fill the opt record
  Opts = utils_opts:optfill(Map, Mods, ?VERSION),
  %case Opts#opts.queuemax of
  %  Nb ->
  %    print(normal, io_lib:fwrite("max queue length: ~p", [Nb]))
  %  0 ->
  %    print(normal, "max queue length: infinite");
  %end,

  % check and initialize the output modules
  Outputs = outs_init(Opts#opts.output, Opts#opts.scaninfo, Opts#opts.outmode),

  % and start the master
  print(normal, "starting master ..."),
  doit(Opts),

  % wait for end
  process_flag(priority, high),
  finishit(Start, Outputs, Opts#opts.outmode, rcv_loop(Opts, Outputs, 0, 0)).

