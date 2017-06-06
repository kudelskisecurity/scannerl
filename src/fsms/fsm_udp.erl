%%% UDP FSM Module

-module(fsm_udp).
-author("David Rossier - david.rossier@kudelskisecurity.com").
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").
-behavior(gen_fsm).

-export([start_link/1, start/1]).
-export([init/1, terminate/3, handle_info/3]).
-export([code_change/4, handle_sync_event/4, handle_event/3]).
-export([connecting/2, callback/2]).

-include("../includes/args.hrl").

% see http://erlang.org/doc/man/inet.html#setopts-2
-define(COPTS, [binary, inet,{recbuf, 65536}, {active, false}]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% debug
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% send debug
debug(Args, Msg) ->
  utils:debug(fpmodules, Msg,
    {Args#args.target, Args#args.id}, Args#args.debugval).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% API calls
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
callback(timeout, Data) when Data#args.packetrcv == 0
    andalso Data#args.retrycnt > 0 andalso Data#args.payload /= << >> ->
  inet:setopts(Data#args.socket, [{active, once}]),
  gen_udp:send(Data#args.socket, Data#args.ipaddr,
    Data#args.cport, Data#args.payload),
  {next_state, callback, Data#args{retrycnt=Data#args.retrycnt-1}, Data#args.timeout};
callback(timeout, Data) ->
  case apply(Data#args.module, callback_next_step, [Data]) of
    {continue, Nbpacket, Payload, ModData} ->
      flush_socket(Data#args.socket),
      inet:setopts(Data#args.socket, [{active, once}]),
      gen_udp:send(Data#args.socket, Data#args.ipaddr, Data#args.cport, Payload),
      {next_state, callback, Data#args{moddata=ModData, payload=Payload,
        nbpacket=Nbpacket}, Data#args.timeout};
    {restart, {Target, Port}, ModData} ->
      Newtarget = case Target == undefined of true -> Data#args.ctarget; false -> Target end,
      Newport = case Port == undefined of true -> Data#args.cport; false -> Port end,
      gen_udp:close(Data#args.socket),
      {next_state, connecting, Data#args{ctarget=Newtarget, cport=Newport,
        moddata=ModData, retrycnt=Data#args.retry,
        datarcv = << >>, payload = << >>, packetrcv=0}, 0};
    {result, Result} ->
      gen_udp:close(Data#args.socket),
      {stop, normal, Data#args{result=Result}} % RESULT
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% gen_fsm modules (http://www.erlang.org/doc/man/gen_fsm.html)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% this is when there's no supervisor
start_link(Args) ->
  gen_fsm:start_link(?MODULE, Args, []).
% this is when it's part of a supervised tree
start([Args]) ->
  gen_fsm:start(?MODULE, Args, []).

flush_socket(Socket) ->
  case gen_udp:recv(Socket, 0, 0) of
    {error, _Reason} ->
      ok;
    {ok, _Result} ->
      flush_socket(Socket)
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% gen_fsm callbacks
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% called by start/start_link
init(Args) ->
  doit(Args#args{ctarget=Args#args.target, cport=Args#args.port, retrycnt=Args#args.retry}).

% start the process
doit(Args) ->
  % first let's call "connect" through "connecting" using a timeout of 0
  debug(Args, io_lib:fwrite("~p on ~p", [Args#args.module, Args#args.ctarget])),
  {ok, connecting, Args, 0}.

% get privport opt
get_privports(true) ->
  [{port, rand:uniform(1024)}];
get_privports(_) ->
  [].

% provide the socket option
get_options(Args) ->
  ?COPTS ++ get_privports(Args#args.privports)
    ++ Args#args.fsmopts.

% State connecting is used to initiate the udp connection
connecting(timeout, Data) ->
  Host = Data#args.ctarget, Timeout = Data#args.timeout,
  case utils_fp:lookup(Host, Timeout, Data#args.checkwww) of
    {ok, Addr} ->
      case gen_udp:open(0, get_options(Data)) of
        {ok, Socket} ->
          % Addr resolved, udp socket reserved, now send.
          {next_state, callback, Data#args{socket=Socket, ipaddr=Addr}, 0 };
          %{next_state, sending, Data#args{socket=Socket, ipaddr=Addr}, 0 };
        {error, Reason} ->
          gen_fsm:send_event(self(), {error, Reason}),
          {next_state, connecting, Data}
      end;
    {error, Reason} ->
      gen_fsm:send_event(self(), {error, Reason}),
      {next_state, connecting, Data}
  end;
% called when source port is already taken
connecting({error, tcp_eacces}, Data)
when Data#args.privports == true, Data#args.eaccess_retry < Data#args.eaccess_max ->
  {next_state, connecting, Data#args{eaccess_retry=Data#args.eaccess_retry+1}, 0};
% called when connection failed
connecting({error, Reason}, Data) ->
  {stop, normal, Data#args{result={{error, unknown}, Reason}}}. % RESULT

%% called by stop
terminate(_Reason, _State, Data) ->
  Result = {Data#args.module, Data#args.target, Data#args.port, Data#args.result},
  debug(Data, io_lib:fwrite("~p done on ~p (outdirect:~p)",
    [Data#args.module, Data#args.target, Data#args.direct])),
  case Data#args.direct of
    true ->
      utils:outputs_send(Data#args.outobj, [Result]);
    false ->
      Data#args.parent ! Result
  end,
  ok.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% event handlers
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% called when a new packet is received
handle_info({udp, Socket, Addr, Port, Packet}, callback, Data)
when (Socket == Data#args.socket) andalso (Addr == Data#args.ipaddr)
  andalso (Port == Data#args.cport) ->
  case Data#args.nbpacket of
    infinity ->
      inet:setopts(Data#args.socket, [{active, once}]),
      {next_state, callback, Data#args{
        datarcv = <<(Data#args.datarcv)/binary, Packet/binary>>,
        packetrcv = Data#args.packetrcv + 1
        }, Data#args.timeout};
    1 -> % It is the last packet to receive
      {next_state, callback, Data#args{
        datarcv = <<(Data#args.datarcv)/binary, Packet/binary>>,
        nbpacket = 0,
        packetrcv = Data#args.packetrcv + 1
        }, 0};
    0 -> % If they didn't want any packet ?
      {stop, normal, Data#args{result={
        {error,up},[toomanypacketreceived, Packet]}}}; % RESULT
    _Cnt -> % They are more packets (maybe)
      inet:setopts(Data#args.socket, [{active, once}]),
      {next_state, callback, Data#args{
        datarcv = <<(Data#args.datarcv)/binary, Packet/binary>>,
        nbpacket=Data#args.nbpacket-1,
        packetrcv = Data#args.packetrcv + 1
        }, Data#args.timeout}
  end;
handle_info(_Msg, _State, Data) ->
  {stop, normal, Data#args{result={{error, unknown}, unexpected_host}}}. % RESULT

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% UNUSED event handlers
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
code_change(_Prev, State, Data, _Extra) ->
  {ok , State, Data}.
handle_sync_event(_Ev, _From, _State, Data) ->
  {stop, unexpectedSyncEvent, Data}.
handle_event(_Ev, _State, Data) ->
  {stop, unexpectedEvent, Data}.

