%%% UDP statem
%%%

-module(statem_udp).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").
-behavior(gen_statem).

-include("../includes/args.hrl").

% gen_statem imports
-export([start_link/1, start/1]).
-export([init/1, terminate/3, code_change/4]).
-export([callback_mode/0]).

% callbacks
-export([connecting/3, callback/3]).

% see http://erlang.org/doc/man/inet.html#setopts-2
-define(COPTS, [binary, inet,{recbuf, 65536}, {active, false}]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% gen_statem specific
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% called by start/start_link
init(Args) ->
  doit(Args#args{ctarget=Args#args.target, cport=Args#args.port, retrycnt=Args#args.retry}).

%% start the process
doit(Args) ->
  % first let's call "connect" through "connecting" using a timeout of 0
  debug(Args, io_lib:fwrite("~p on ~p", [Args#args.module, Args#args.ctarget])),
  {ok, connecting, Args, 0}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% fsm callbacks
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% called for sending first packet
callback(timeout, _EventContent, Data) when Data#args.packetrcv == 0
    andalso Data#args.retrycnt > 0 andalso Data#args.payload /= << >> ->
  inet:setopts(Data#args.socket, [{active, once}]),
  gen_udp:send(Data#args.socket, Data#args.ipaddr,
    Data#args.cport, Data#args.payload),
  {next_state, callback, Data#args{retrycnt=Data#args.retrycnt-1}, Data#args.timeout};
%% called for sending additional packet when needed
callback(timeout, _EventContent, Data) ->
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
      {stop, normal, Data#args{result=Result}}
  end;
%% called when a new packet is received
callback(info, {udp, Socket, Addr, Port, Packet}, Data)
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
        {error,up},[toomanypacketreceived, Packet]}}};
    _Cnt -> % They are more packets (maybe)
      inet:setopts(Data#args.socket, [{active, once}]),
      {next_state, callback, Data#args{
        datarcv = <<(Data#args.datarcv)/binary, Packet/binary>>,
        nbpacket=Data#args.nbpacket-1,
        packetrcv = Data#args.packetrcv + 1
        }, Data#args.timeout}
  end;
callback(info, {udp, _, _, _, _}, Data) ->
  {stop, normal, Data#args{result={{error, unknown}, unexpected_host}}};
callback(Event, EventContent, Data) ->
  {stop, normal, Data#args{result={{error, unknown}, [unexpected_event, Event, EventContent, Data]}}}.

%% State connecting is used to initiate the udp connection
connecting(timeout, _, Data) ->
  Host = Data#args.ctarget, Timeout = Data#args.timeout,
  case utils_fp:lookup(Host, Timeout, Data#args.checkwww) of
    {ok, Addr} ->
      case gen_udp:open(0, get_options(Data)) of
        {ok, Socket} ->
          % Addr resolved, udp socket reserved, now send.
          {next_state, callback, Data#args{socket=Socket, ipaddr=Addr}, 0 };
          %{next_state, sending, Data#args{socket=Socket, ipaddr=Addr}, 0 };
        {error, Reason} ->
          gen_statem:cast(self(), {error, Reason}),
          {next_state, connecting, Data}
      end;
    {error, Reason} ->
      gen_statem:cast(self(), {error, Reason}),
      {next_state, connecting, Data}
  end;
%% called when source port is already taken
connecting(cast, {error, tcp_eacces}, Data)
when Data#args.privports == true, Data#args.eaccess_retry < Data#args.eaccess_max ->
  {next_state, connecting, Data#args{eaccess_retry=Data#args.eaccess_retry+1}, 0};
%% called when connection failed
connecting(cast, {error, Reason}, Data) ->
  {stop, normal, Data#args{result={{error, unknown}, Reason}}}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% utils
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% get privport opt
get_privports(true) ->
  [{port, rand:uniform(1024)}];
get_privports(_) ->
  [].

%% provide the socket option
get_options(Args) ->
  ?COPTS ++ get_privports(Args#args.privports)
    ++ Args#args.fsmopts.

%% receive everything available from the socket
flush_socket(Socket) ->
  case gen_udp:recv(Socket, 0, 0) of
    {error, _Reason} ->
      ok;
    {ok, _Result} ->
      flush_socket(Socket)
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% helper for the fsm
%% gen_statem http://erlang.org/doc/man/gen_statem.html
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% this is when there's no supervisor
start_link(Args) ->
  gen_statem:start_link(?MODULE, Args, []).
%% this is when it's part of a supervised tree
start([Args]) ->
  gen_statem:start(?MODULE, Args, []).

%% set the callback mode for gen_statem
callback_mode() ->
    state_functions.

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

%% unused callback
code_change(_Prev, State, Data, _Extra) ->
  {ok , State, Data}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% debug
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% send debug
debug(Args, Msg) ->
  utils:debug(fpmodules, Msg,
    {Args#args.target, Args#args.id}, Args#args.debugval).

