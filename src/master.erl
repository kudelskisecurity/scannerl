% the master in the master/slave architecture of scannerl

-module(master).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-export([master/1, listen/2]).
-include("includes/opts.hrl").

-define(CHECKTO, 3000). % ms
-define(MAXWAIT, 20000). % ms
-define(ENDTO, 10000). % ms
-define(ERLEXT, ".erl").
% that's the range start for TCP communication
% will be expanded to ?PORTMIN+nb_slaves for the max
-define(PORTMIN, 11100).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% remote related functions
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% this loads all modules for this specific node
rem_load_modules(_, []) ->
  ok;
rem_load_modules(Node, [M|Rest]) ->
  {Mod, Bin, _} = code:get_object_code(M),
  rpc:call(Node, code, purge, [Mod]),
  rpc:call(Node, erlang, load_module, [Mod, Bin]),
  rem_load_modules(Node, Rest).

wait_for_slave(Tot, Cnt, Cntlist, _Mods, _Nosafe) when Cnt == Tot ->
  case cntlist:count(Cntlist) of
    0 ->
      print(error, "no viable host found"),
      {error, Cntlist};
    _ ->
      {ok, Cntlist}
  end;
wait_for_slave(Tot, Cnt, Cntlist, Modules, Nosafe) ->
  receive
    {ok, Node, H, _Name} ->
      net_kernel:connect_node(Node),
      rem_load_modules(Node, Modules),
      % then register master and scannerl on remote
      rpc:call(Node, global, register_name,
        [master, global:whereis_name(listener)]),
      rpc:call(Node, global, register_name,
        [scannerl, global:whereis_name(scannerl)]),
      New = cntlist:update_key(Cntlist, H, Node),
      wait_for_slave(Tot, Cnt+1, New, Modules, Nosafe);
    {error, Reason, H, Name} when Nosafe ->
      print(warning, io_lib:fwrite("host ~p (name:~p) failed to start: ~p - continue ...",
        [H, Name, Reason])),
      New = cntlist:remove_key(Cntlist, H),
      wait_for_slave(Tot, Cnt+1, New, Modules, Nosafe);
    {error, Reason, H, Name} ->
      print(error, io_lib:fwrite("unable to start host ~p (name:~p): ~p",
        [H, Name, Reason])),
      {error, Cntlist}
  after
    ?MAXWAIT ->
      print(error, io_lib:fwrite("max timeout (~ps) reached when waiting for slaves (got ~p/~p)",
        [?MAXWAIT / 1000, Cnt, Tot])),
      {error, Cntlist}
  end.

% start a list of slave
start_slave_th([], Mods, Tot, Slaves, _Basename, Nosafe, _Dbg) ->
  wait_for_slave(Tot, 0, Slaves, Mods, Nosafe);
start_slave_th([H|T], Modules, Cnt, Slaves, Basename, Nosafe, Dbg) ->
  Name = lists:concat([Basename, "-slave-", integer_to_list(Cnt)]),
  spawn_link(utils_slave, start_link_th, [H, Name, ?PORTMIN, Dbg, self()]),
  start_slave_th(T, Modules, Cnt+1, Slaves, Basename, Nosafe, Dbg).

% start all slave nodes using process
start_slaves(Slaves, Modules, Basename, Nosafe, Dbg) ->
  start_slave_th(cntlist:flattenkeys(Slaves), Modules, 0, Slaves,
    Basename, Nosafe, Dbg).

% stop all slave nodes
stop_slaves([], _Dbg) ->
  ok;
stop_slaves([H|T], Dbg) ->
  spawn_link(utils_slave, stop, [H, Dbg]),
  stop_slaves(T, Dbg).

% start a broker on each node
start_brokers([], _, _, Agg) ->
  Agg;
start_brokers([H|T], Opts, Cnt, Agg) ->
  Id = "ID" ++ integer_to_list(Cnt),
  Pid = spawn_link(H, broker, scan, [Opts#opts{user=Id}]),
  start_brokers(T, Opts, Cnt+1, Agg ++ [Pid]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Utilities
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% globally register master as myself
register_entry(Pid, Name) ->
  yes = global:register_name(Name, Pid),
  global:sync().

% return our hostname
my_hostname() ->
  {ok, Hostname} = inet:gethostname(),
  Hostname.

% randomize a list
rnd_list(List) ->
  [X||{_,X} <- lists:sort([{rand:uniform(), N} || N <- List])].

print(myerror, Msg) ->
  io:put_chars(standard_error, Msg);
print(us, Msg) ->
  M = io_lib:fwrite("<~s> [M]     ~s\n", [utils:get_ts(), Msg]),
  io:put_chars(standard_error, M);
print(error, Msg) ->
  M = io_lib:fwrite("<~s> [M]>[E] ~s\n", [utils:get_ts(), Msg]),
  io:put_chars(standard_error, M);
print(warning, Msg) ->
  M = io_lib:fwrite("[WARNING] ~s\n", [Msg]),
  io:put_chars(standard_error, M);
print(info, Msg) ->
  M = io_lib:fwrite("<~s> [M]>[I] ~s\n", [utils:get_ts(), Msg]),
  io:put_chars(standard_error, M);
print(result, Msg) ->
  M = io_lib:fwrite("~s\n", [Msg]),
  io:put_chars(standard_error, M);
print(_, _) ->
  ok.

% print timestamp in nice format
ts() ->
  print(us, utils:get_ts()).

% pretty print duration
duration(Start) ->
  Duration = calendar:datetime_to_gregorian_seconds(calendar:universal_time()) - Start,
  DateTime = calendar:gregorian_seconds_to_datetime(Duration),
  {{_Y,_M,_D}, {H,Min,S}} = DateTime,
  [H, Min, S].

% get current process queue cnt
msg_queue_len() ->
  {_, Cnt} = erlang:process_info(self(), message_queue_len),
  Cnt.

% get epoch
epoch() ->
  {M, S, _} = os:timestamp(),
  (M*1000000)+S.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Communication
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% listen for slave's messages
listen(TotSlave, Opts) ->
  rcv_loop(TotSlave, Opts, []),
  flush_msg(msg_queue_len(), Opts),
  global:whereis_name(main) ! {quit}.

% flush message in the queue
flush_msg(0, _) ->
  ok;
flush_msg(_, Opts) ->
  rcv_loop(0, Opts, []),
  flush_msg(msg_queue_len(), Opts).

% wait for and answer to message(s)
rcv_loop(0, _Opts, _Pids) ->
  ok;
rcv_loop(CntSlave, Opts, Pids) ->
  receive
    {totchange, New} ->
      % update the number of nodes (especially for --nosafe)
      rcv_loop(New, Opts, Pids);
    {pids, List} ->
      % update the pids
      rcv_loop(CntSlave, Opts, List);
    {progress, _From, Id, Msg} ->
      % sent by myself (other thread)
      %print(info, io_lib:fwrite("[progress][~p|~s] ~s", [From, Id, Msg])),
      print(info, io_lib:fwrite("[progress][~s] ~s", [Id, Msg])),
      rcv_loop(CntSlave, Opts, Pids);
    {info, From, Id, "done"} ->
      % sent by broker
      utils:debug(master,
        io_lib:fwrite("[~p|~s] is done !", [From, Id]), {}, Opts#opts.debugval),
      rcv_loop(CntSlave-1, Opts, Pids);
    {info, From, Id, Data} ->
      % sent by broker
      print(info, io_lib:fwrite("[~p|~s]: ~s", [From, Id, Data])),
      rcv_loop(CntSlave, Opts, Pids);
    {debug, From, Msg} ->
      % debug message from broker
      utils:debug_print(From, Msg),
      rcv_loop(CntSlave, Opts, Pids);
    {message, {error, Proto, Port, Reason}} ->
      print(error, io_lib:fwrite("cannot listen on ~s/~p: ~p", [Proto, Port, Reason])),
      rcv_loop(CntSlave, Opts, Pids);
    {message, {ok, Protocol, Ip, Port}} ->
      print(us, io_lib:fwrite("listen on ~s ~s/~p", [Ip, Protocol, Port])),
      rcv_loop(CntSlave, Opts, Pids);
    {message, {message, "progress"}} ->
      print(us, "progress triggered"),
      trigger_progress(true, Pids),
      rcv_loop(CntSlave, Opts, Pids);
    {message, {message, "abort"}} ->
      % received by the message listener
      case Pids of
        [] ->
          % called at the end of the process
          print(info, "[!!] cannot cancel, process is terminating");
        _ ->
          print(info, "[!!] send cancel to all slaves"),
          [X ! {cancel} || X <- Pids]
      end,
      rcv_loop(CntSlave, Opts, Pids);
    _ ->
      rcv_loop(CntSlave, Opts, Pids)
  after
    ?CHECKTO ->
      rcv_loop(CntSlave, Opts, Pids)
  end.

% send message {progress} to all slaves
trigger_progress(false, _) ->
  ok;
trigger_progress(true, Pids) ->
  print(info, io_lib:fwrite("[progress][M] ~p slave(s)", [length(Pids)])),
  global:whereis_name(scannerl) ! {progress},
  [X ! {progress} || X <- Pids].

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Slave processing
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% get a slave (from a list of string) and add it to a cntlist
get_slave([], Agg) ->
  Agg;
get_slave([Entry|T], Agg) ->
  case string:str(Entry, "*") of
    0 ->
      get_slave(T, cntlist:add(Agg, Entry, 1));
    _ ->
      [Node, Nb] = string:tokens(Entry, "*"),
      get_slave(T, cntlist:add(Agg, Node, list_to_integer(Nb)))
  end.

% get slaves from a file
slaves_from_file(nil) ->
  {ok, []};
slaves_from_file(Path) ->
  case utils:read_lines(Path) of
    {ok, Lines} ->
      {ok, get_slave(Lines, [])};
   {error, Reason} ->
      {error, Reason}
  end.

% get slaves from CLI and Path
get_slaves(Slaves, Path) ->
  Sl1 = get_slave(Slaves, []),
  case slaves_from_file(Path) of
    {ok, Sl2} ->
      Res = cntlist:merge(lists:flatten(Sl1 ++ Sl2)),
      case cntlist:count(Res) of
        0 ->
          cntlist:add([], my_hostname(), 1);
        _ ->
          Res
      end;
    {error, Reason} ->
      print(myerror, io_lib:fwrite("[ERROR] cannot get slaves from ~p: ~p~n",
        [Path, Reason])),
      []
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Target processing
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% get a list of stripped lines that represent a target
targets_from_file(nil) ->
  [];
targets_from_file(Path) ->
  case utils:read_lines(Path) of
    {ok, Lines} ->
      Lines;
    {error, Reason} ->
      print(myerror, io_lib:fwrite("[ERROR] cannot get targets from ~p: ~p~n",
        [Path, Reason])),
      []
  end.

% parse ip/cidr and sub-divide in Minrange
process_targets([], _, _, _) ->
  [];
process_targets([H|T], Agg, Minrange, Defport) ->
  case tgt:parse_ip(H, Defport) of
    {ok, Tgt} ->
      tgt:minrange(Tgt, Minrange) ++ process_targets(T, Agg, Minrange, Defport);
    {error, Reason} ->
      print(myerror, io_lib:fwrite("[ERROR] cannot parse ~p: ~p~n",
        [H, Reason])),
      process_targets(T, Agg, Minrange, Defport)
  end.

% parse domains
process_domains([], _, _, _) ->
  [];
process_domains([H|T], Agg, Minrange, Defport) ->
  [tgt:parse_domain(H, Defport)] ++ process_domains(T, Agg, Minrange, Defport).

% here we distribute Len by Len the targets to the different
% hosts
targets_to_nodes([N|[]], Targets, {Start, Len}, Nodes) ->
  Sub = lists:sublist(Targets, Start, Len),
  %io:fwrite("sending ~p target(s) to ~p~n", [length(Sub), N]),
  N ! {targets, Sub},
  case Start+Len > length(Targets) of
    true ->
      ok;
    false ->
      targets_to_nodes_rest(Nodes, Targets, {Start+Len, Len})
  end;
targets_to_nodes([N|Rest], Targets, {Start, Len}, Nodes) ->
  Sub = lists:sublist(Targets, Start, Len),
  %io:fwrite("sending ~p target(s) to ~p~n", [length(Sub), N]),
  N ! {targets, Sub},
  case Start+Len > length(Targets) of
    true ->
      ok;
    false ->
      targets_to_nodes(Rest, Targets, {Start+Len, Len}, Nodes)
  end.

% this is the rest of the targets when the division is not
% finished
targets_to_nodes_rest([N|Nodes], Targets, {Start, Len})
when Start =< length(Targets) ->
  Sub = lists:sublist(Targets, Start, Len),
  %io:fwrite("sending ~p target(s) to ~p~n", [length(Sub), N]),
  N ! {targets, Sub},
  targets_to_nodes_rest(Nodes, Targets, {Start+Len, Len});
targets_to_nodes_rest(_, _, _) ->
  ok.

% push the targets to the nodes
push([], _, _) ->
  ok;
push(_, [], _) ->
  ok;
push(Nodes, Targets, Func) ->
  Exploded = Func(Targets),
  Rnd = rnd_list(Exploded),
  Len = case length(Nodes) > length(Rnd) of true -> 1; false -> length(Rnd) div length(Nodes) end,
  targets_to_nodes(Nodes, Rnd, {1, Len}, Nodes).

push_file(nil, _Nodes, _Func, _Dbg) ->
  ok;
push_file([], _Nodes, _Func, _Dbg) ->
  ok;
push_file([H|T], Nodes, Func, Dbg) ->
  utils:debug(master, io_lib:fwrite("loading file: ~p", [H]), {}, Dbg),
  Tgts = targets_from_file(H),
  utils:debug(master, io_lib:fwrite("pushing loaded target(s) from: ~p", [H]), {}, Dbg),
  push(Nodes, Tgts, Func),
  erlang:garbage_collect(),
  push_file(T, tl(Nodes) ++ [hd(Nodes)], Func, Dbg).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Entry point
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% wait end of scan
wait_end(Progress, Pids, Opts) ->
  receive
    {pause} ->
      % output wants to pause
      pause_all(Pids, true, Opts),
      wait_end(Progress, Pids, Opts);
    {resume} ->
      % output wants to resume
      pause_all(Pids, false, Opts),
      wait_end(Progress, Pids, Opts);
    {quit} ->
      ok
  after
    ?ENDTO ->
      % this only here to trigger progress
      trigger_progress(Progress, Pids),
      wait_end(Progress, Pids, Opts)
  end.

pause_all(Pids, Flag, Opts) ->
  case Flag of
    true ->
      utils:debug(master, "pausing ...", {}, Opts#opts.debugval),
      [X ! {pause} || X <- Pids];
    false ->
      utils:debug(master, "resuming ...", {}, Opts#opts.debugval),
      [X ! {resume} || X <- Pids]
  end.

% start the master
master(Opts) ->
  ts(),
  Id = integer_to_list(epoch()),
  register_entry(self(), main),
  MyNodeName = list_to_atom(lists:concat([Id, "master"])),
  net_kernel:start([MyNodeName, shortnames]),

  Start = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
  Slaves = get_slaves(Opts#opts.slave, Opts#opts.slavefile),
  print(us, io_lib:fwrite("SCANNERL started for Module ~s", [Opts#opts.module])),

  application:set_env(kernel, inet_dist_listen_min, ?PORTMIN),
  application:set_env(kernel, inet_dist_listen_max, ?PORTMIN+cntlist:count(Slaves)),

  % starting slave nodes
  SlaveTimestamp = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
  register_entry(spawn_link(?MODULE, listen,
    [cntlist:count(Slaves), Opts]), listener),
  print(us, io_lib:fwrite("starting ~p slave's node(s) on ~p host(s)",
    [cntlist:count(Slaves), length(Slaves)])),
  case Opts#opts.maxchild of
    0 ->
      print(us, io_lib:fwrite("max process per node: ~p", [unlimited]));
    Nb ->
      print(us, io_lib:fwrite("max process per node: ~p", [Nb]))
  end,

  {Ret, Nodes} = start_slaves(Slaves, Opts#opts.slmodule, Id, Opts#opts.nosafe, Opts#opts.debugval),
  print(us, io_lib:fwrite("slave's node(s) started in: ~2..0w:~2..0w:~2..0w",
    duration(SlaveTimestamp))),
  % update total number of slave
  global:whereis_name(listener) ! {totchange, cntlist:count(Nodes)},
  % check nodes are ready to scan
  case Ret of
    error ->
      % handle error of node start
      stop_slaves(cntlist:flattenkeys(Nodes), Opts#opts.debugval),
      print(error, "slave's node(s) start failed"),
      global:whereis_name(scannerl) ! {done, error};
    ok ->
      % start the supervisor(s)
      print(us, io_lib:fwrite("starting ~p supervisor(s)",
        [cntlist:count(Nodes)])),
      Pids = rnd_list(start_brokers(cntlist:flatten(Nodes), Opts, 0, [])),
      SlaveDuration = duration(SlaveTimestamp),
      TargetTimestamp = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
      % push the target(s) from CLI
      print(us, "parse and push target(s)"),
      push(Pids, Opts#opts.target,
        fun(X) ->  process_targets(X, [], Opts#opts.minrange, Opts#opts.port) end),
      push(Pids, Opts#opts.domain,
        fun(X) ->  process_domains(X, [], Opts#opts.minrange, Opts#opts.port) end),
      % push the target(s) from file
      print(us, "parse and push target(s) from file"),
      push_file(Opts#opts.targetfile, Pids,
        fun(X) ->  process_targets(X, [], Opts#opts.minrange, Opts#opts.port) end,
        Opts#opts.debugval),
      push_file(Opts#opts.domainfile, Pids,
        fun(X) ->  process_domains(X, [], Opts#opts.minrange, Opts#opts.port) end,
        Opts#opts.debugval),
      TargetDuration = duration(TargetTimestamp),
      print(us, io_lib:fwrite("target(s) parsed and pushed in: ~2..0w:~2..0w:~2..0w",
        TargetDuration)),
      % update the slave pids on the listener
      global:whereis_name(listener) ! {pids, Pids},
      % start the message server
      spawn_link(utils_msgserver, listen_udp, [global:whereis_name(listener), Opts#opts.msg_port]),
      % start the fingerprinting process
      [X ! {done} || X <- Pids],
      print(us, "started ..."),
      % wait for end
      wait_end(Opts#opts.progress, Pids, Opts),
      % stop slave's node(s)
      utils:debug(master, io_lib:fwrite("stopping nodes: ~p", [Nodes]), {}, Opts#opts.debugval),
      stop_slaves(cntlist:flattenkeys(Nodes), Opts#opts.debugval),
      print(us, io_lib:fwrite("target setup duration: ~2..0w:~2..0w:~2..0w",
        TargetDuration)),
      print(us, io_lib:fwrite("slave setup duration: ~2..0w:~2..0w:~2..0w",
        SlaveDuration)),
      % stop the message server
      utils_msgserver:stop_udp(Opts#opts.msg_port),
      % gather info and terminate
      global:whereis_name(scannerl) ! {done, {cntlist:count(Nodes)}}
    end,
  print(us, io_lib:fwrite("duration: ~2..0w:~2..0w:~2..0w", duration(Start))),
  ts().

