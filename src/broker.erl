%% the broker for the slave

-module(broker).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-export([scan/1]).
-include("includes/opts.hrl").
-include("includes/args.hrl").
-include("includes/erlversion.hrl").

% check children every CHECKTO
-define(CHECKTO, 3000).
-define(PROGRESS_MOD, 1000).

-ifdef(USE_GENFSM).
  -define(TCPFSM, fsm_tcp).
  -define(UDPFSM, fsm_udp).
  -define(SSLFSM, fsm_ssl).
-else.
  -define(TCPFSM, statem_tcp).
  -define(UDPFSM, statem_udp).
  -define(SSLFSM, statem_ssl).
-endif.

% the option for this scan
-record(obj, {
    args,         % the args to pass to the children
    mdone,        % master is done pushing
    dry,          % dry run
    debugval,     % debug val
    pause,        % scan paused
    tcnt,         % target received count
    maxchild,     % max nb of child to spin
    outputs,      % the output modules
    parent,       % to whom result must be sent
    outbufsz,     % how many result to bufferize
    outbuf,       % output buffering
    cancel=false, % cancel has been called
    id            % this node id
  }).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% killing children
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% when master decides to cancel the whole process,
% kill the children
kill_child(_Master, []) ->
  %send_msg(Master, info, "done killing all children"),
  ok;
kill_child(Master, [H|T]) ->
  {Id, _Child, _Type, _Modules} = H,
  case Id of
    undefined ->
      ok;
    _ ->
      supervisor:terminate_child(scannerl_worker_sup, Id)
      %send_msg(Master, info, io_lib:fwrite("killing ~p", [Id]))
  end,
  kill_child(Master, T).

kill_children(Id) ->
  send_msg(Id, info, "KILLING ALL PROCESSES"),
  kill_child(Id, supervisor:which_children(scannerl_worker_sup)).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% start child
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% add a new child to process a new target
add_child(Target, Args, Obj) ->
  utils:debug(broker,
    io_lib:fwrite("new target started: ~p", [Target]), {Obj#obj.id}, Obj#obj.debugval),
  List = tgt:get_tgts(Target),
  [spawn_link(supervisor, start_child, [scannerl_worker_sup, [
    Args#args{target=T, port=P, parent=Obj#obj.parent}]]) || {T, P} <- List],
  length(List).

% add new children for each of these targets
add_childs([], _, Agg, _) ->
  Agg;
add_childs([H|T], _Arg, Agg, Obj) when Obj#obj.pause == true ->
  self() ! {targets, [H|T]},
  Agg;
add_childs([H|T], Arg, Agg, Obj) ->
  case Obj#obj.maxchild /= 0 andalso get_children_count() >= Obj#obj.maxchild of
    true ->
      self() ! {targets, [H|T]},
      Agg;
    false ->
      Cnt = add_child(H, Arg, Obj),
      add_childs(T, Arg, Agg+Cnt, Obj)
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% utilities
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% return the number of live chidren under supervision
% make sure to catch exception of type "noproc" when
% no supervisor actually exists.
get_active_children_count() ->
  try
    proplists:get_value(active, supervisor:count_children(scannerl_worker_sup))
  catch
    _:_ ->
      0
  end.
get_children_count() ->
  try
    proplists:get_value(workers, supervisor:count_children(scannerl_worker_sup))
  catch
    _:_ ->
      0
  end.

% get the number of targets in queue
% because we might have multiple targets per message
% in the queue. However this is costly !
sub_nb_queued_targets([], Agg) ->
  Agg;
sub_nb_queued_targets([{targets, List}|T], Agg) ->
  sub_nb_queued_targets(T, Agg + length(List));
sub_nb_queued_targets([_H|T], Agg) ->
  sub_nb_queued_targets(T, Agg).

nb_queued_targets() ->
  {_, Msgs} = erlang:process_info(self(), messages),
  sub_nb_queued_targets(Msgs, 0).

get_percent(Val, 0) ->
  io_lib:fwrite("~p/?%", [Val]);
get_percent(Val, Tot) ->
  Percent = Val * 100 / Tot,
  io_lib:fwrite("~.2f%", [Percent]).


% return the length of the message queue
msg_queue_len() ->
  {_, Cnt} = erlang:process_info(self(), message_queue_len),
  Cnt.

% send message to master
send_msg(Id, info, "done") ->
  global:whereis_name(master) ! {info, node(), Id, "done"};
send_msg(Id, progress, Msg) ->
  Dummy = io_lib:format("~s", [Msg]),
  try
    global:whereis_name(master) ! {progress, node(), Id, Dummy}
  catch
    _:_ ->
      ok
  end;
send_msg(Id, Type, Msg) ->
  Dummy = io_lib:format("~s", [Msg]),
  global:whereis_name(master) ! {Type, node(), Id, Dummy}.

% set hardtimeout timer
set_hardtimeout(0) ->
  ok;
set_hardtimeout(Hardtimeout) ->
  {ok, _} = timer:send_after(Hardtimeout, {hardtimeout}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% communication
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% wait for all children to be done
% gets only called when master is done pushing targets
wait_exit(Obj, _) when Obj#obj.cancel ->
  utils:debug(broker, "cancelled", {Obj#obj.id}, Obj#obj.debugval),
  outs_send(Obj#obj.outputs, {}, Obj#obj.outbuf, Obj#obj.outbufsz);
wait_exit(Obj, 0) ->
  utils:debug(broker, "flushing", {Obj#obj.id}, Obj#obj.debugval),
  flush_msg(Obj, msg_queue_len()),
  outs_send(Obj#obj.outputs, {}, Obj#obj.outbuf, Obj#obj.outbufsz);
wait_exit(Obj, _) ->
  Nobj = rcv_loop(Obj),
  wait_exit(Nobj, get_active_children_count()).

% make sure there's no message left in queue
flush_msg(_, 0) ->
  ok;
flush_msg(Obj, _) ->
  rcv_loop(Obj),
  flush_msg(Obj, msg_queue_len()).

% start listening for commands
listen(Obj, _) when Obj#obj.cancel ->
  utils:debug(broker, "cancelled", {Obj#obj.id}, Obj#obj.debugval),
  wait_exit(Obj, get_active_children_count());
listen(Obj, true) ->
  % master is done, wait for all children and quit
  utils:debug(broker, "wait for children to finish", {Obj#obj.id}, Obj#obj.debugval),
  wait_exit(Obj, get_active_children_count());
listen(Obj, false) ->
  Nobj = rcv_loop(Obj),
  listen(Nobj, Nobj#obj.mdone).

rcv_loop(Obj) ->
  receive
    {pause} ->
      % received by master
      utils:debug(broker, "pausing", {Obj#obj.id}, Obj#obj.debugval),
      rcv_loop(Obj#obj{pause=true});
    {resume} ->
      % received by master
      utils:debug(broker, "resuming", {Obj#obj.id}, Obj#obj.debugval),
      erlang:garbage_collect(),
      rcv_loop(Obj#obj{pause=false});
    {done} ->
      % master message done pushing target
      utils:debug(broker, "done received from master", {Obj#obj.id}, Obj#obj.debugval),
      rcv_loop(Obj#obj{mdone=true});
    {cancel} ->
      % master message to cancel
      send_msg(Obj#obj.id, info, "cancel received"),
      utils:debug(broker, "cancel received from master", {Obj#obj.id}, Obj#obj.debugval),
      kill_children(Obj#obj.id),
      rcv_loop(Obj#obj{cancel=true});
    {hardtimeout} ->
      % self message to stop everything
      utils:debug(broker, "hard timeout !", {Obj#obj.id}, Obj#obj.debugval),
      send_msg(Obj#obj.id, hardtimeout, []),
      kill_children(Obj#obj.id),
      rcv_loop(Obj#obj{cancel=true});
    {progress} ->
      % message from master to give progress
      % and send it to master
      Nbtgts = nb_queued_targets(),
      Proc = Obj#obj.tcnt,
      Percent = get_percent(Proc, Nbtgts + Proc),
      Msg = io_lib:fwrite("[~s] queue_len:~p|queued_tgts:~p|done_tgts:~p|children:~p/~p",
        [Percent, msg_queue_len(), Nbtgts, Obj#obj.tcnt,
        get_active_children_count(), get_children_count()]),
      send_msg(Obj#obj.id, progress, Msg),
      rcv_loop(Obj);
    {targets, Targets} when Obj#obj.cancel == false ->
      % master message for a new target
      case Obj#obj.dry of
        false ->
          Nb = add_childs(Targets, Obj#obj.args, 0, Obj),
          Cnt = Obj#obj.tcnt + Nb,
          rcv_loop(Obj#obj{tcnt=Cnt});
        true ->
          rcv_loop(Obj)
      end;
    Result = {_, _, _, {{_, _}, _}} ->
      % new result received
      Buf = outs_send(Obj#obj.outputs, Result, Obj#obj.outbuf, Obj#obj.outbufsz),
      rcv_loop(Obj#obj{outbuf=Buf});
    _ ->
      Obj
  after
    ?CHECKTO ->
      Obj
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% output modules
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
outs_init(_, _, Outmode) when Outmode == 0 ->
  {ok, []};
outs_init(Outs, Scaninfo, _) ->
  utils:outputs_init(Outs, Scaninfo).

outs_clean(_, Outmode) when Outmode == 0 ->
  ok;
outs_clean(Outs, _) ->
  utils:outputs_clean(Outs).

outs_send(_Outs, {}, [], _Sz) ->
  ok;
outs_send(Outs, {}, Buffer, _Sz) ->
  utils:outputs_send(Outs, Buffer);
outs_send(_Outs, Msg, Buffer, Sz) when length(Buffer) < Sz ->
  Buffer ++ [Msg];
outs_send(Outs, Msg, Buffer, _Sz) ->
  utils:outputs_send(Outs, Buffer ++ [Msg]),
  [].

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% entry point
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
get_module_args(Opts, Id, Outs) ->
  Direct = case Opts#opts.outmode of 1 -> true; _ -> false end,
  #args{module=Opts#opts.module, id=Id, port=Opts#opts.port,
        timeout=Opts#opts.timeout, debugval=Opts#opts.debugval,
        retry=Opts#opts.retry, arguments=Opts#opts.modarg,
        checkwww=Opts#opts.checkwww, outobj=Outs, direct=Direct,
        privports=Opts#opts.privports, fsmopts=Opts#opts.fsmopts,
        maxpkt=Opts#opts.maxpkt, sockopt=Opts#opts.sockopt}.

% starting the supervisor
start_supervisor(Module, Id) ->
  Args = apply(Module, get_default_args, []),
  case Args#args.type of
    tcp ->
      scannerl_worker_sup:start_link({?TCPFSM,start_link,[]});
    udp ->
      scannerl_worker_sup:start_link({?UDPFSM,start_link,[]});
    ssl ->
      scannerl_worker_sup:start_link({?SSLFSM,start_link,[]});
    other ->
      scannerl_worker_sup:start_link({Module,start_link,[]});
    _ ->
      send_msg(Id, info, "ERROR: Invalid fsm TYPE. Should be tcp, udp or ssl."),
      send_msg(Id, info, "done")
  end.

% called by the master
scan(Opts) ->
  % first initialize output module if needed
  case outs_init(Opts#opts.output, Opts#opts.scaninfo, Opts#opts.outmode) of
    {ok, Outputs} ->
      % init internal record
      Parent = case Opts#opts.outmode of 0 -> global:whereis_name(scannerl); _ -> self() end,
      Obj = #obj{args=get_module_args(Opts, Opts#opts.user, Outputs), mdone=false, dry=Opts#opts.dry,
        debugval=Opts#opts.debugval, id=Opts#opts.user, tcnt=0, maxchild=Opts#opts.maxchild,
        parent=Parent, outputs=Outputs, outbuf=[], outbufsz=Opts#opts.outmode},
      start_supervisor(Opts#opts.module, Opts#opts.user),
      set_hardtimeout(Opts#opts.hardtimeout),
      utils:debug(broker, "start listening for message from master/slave",
        {Obj#obj.id}, Obj#obj.debugval),
      % start listening for message (from master mostly)
      listen(Obj, Obj#obj.mdone),
      % clean output
      outs_clean(Outputs, Opts#opts.outmode),
      % we're done
      send_msg(Obj#obj.id, info, "done");
    {error, Reason} ->
      send_msg(Opts#opts.user, info,
        io_lib:fwrite("[ERROR] output setup failed: ~p", [Reason])),
      send_msg(Opts#opts.user, info, "done"),
      ok
  end.

