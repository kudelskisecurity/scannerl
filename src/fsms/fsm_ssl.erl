%%% ssl FSM Reference
%%%
%%%
%%% specific option can be set to control how
%%% the remote certificate is checked:
%%%   {sslcheck, true}: check the certificate validity
%%%   {sslcheck, full}: the above plus the domain check
%%%   {sslcheck, false}: disable ssl checking
%%% default is "true"
%%%

-module(fsm_ssl).
-author("David Rossier - david.rossier@kudelskisecurity.com").
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").
-behavior(gen_fsm).

-include("../includes/args.hrl").

-export([start_link/1, start/1]).
-export([init/1, terminate/3, handle_info/3]).
-export([code_change/4, handle_sync_event/4, handle_event/3]).
-export([connecting/2, receiving/2, callback/2]).

% see http://erlang.org/doc/man/inet.html#setopts-2
-define(COPTS, [binary, {packet, 0}, inet,{recbuf, 65536}, {active, false}, {reuseaddr, true}]).

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
send_data(Data) ->
  case ssl:send(Data#args.socket, Data#args.payload) of
    ok ->
      {next_state, receiving, Data#args{
        sending=true,
        datarcv = << >>,
        packetrcv = 0
        },
      0};
    {error, Reason} ->
      {next_state, callback, Data#args{sndreason=Reason}, 0}
  end.


% Defines what to do next.
callback(timeout, Data) when Data#args.retrycnt > 0 andalso Data#args.packetrcv == 0
    andalso Data#args.payload /= << >>  ->
  send_data(Data#args{retrycnt=Data#args.retrycnt-1});
callback({error, Reason}, Data) ->
  ssl:close(Data#args.socket),
  {stop, normal, Data#args{result={{error, up}, Reason}}};
callback(timeout, Data) ->
  case apply(Data#args.module, callback_next_step, [Data]) of
    {continue, Nbpacket, Payload, ModData} ->
      %flush_socket(Data#args.socket),
      send_data(Data#args{nbpacket=Nbpacket, payload=Payload, moddata=ModData});
    {restart, {Target, Port}, ModData} ->
      Newtarget = case Target == undefined of true -> Data#args.ctarget; false -> Target end,
      Newport = case Port == undefined of true -> Data#args.cport; false -> Port end,
      ssl:close(Data#args.socket),
      {next_state, connecting, Data#args{ctarget=Newtarget, cport=Newport,
        moddata=ModData, sending=false, retrycnt=Data#args.retry,
        datarcv = << >>, payload = << >>, packetrcv=0}, 0};
    {result, Result} ->
      ssl:close(Data#args.socket),
      {stop, normal, Data#args{result=Result}} % RESULT
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% gen_fsm modules (http://www.erlang.org/doc/man/gen_fsm.html)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% this is when there's no supervisor Args is an #args record
start_link(Args) ->
  gen_fsm:start_link(?MODULE, Args, []).
% this is when it's part of a supervised tree
start([Args]) ->
  gen_fsm:start(?MODULE, Args, []).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% gen_fsm callbacks
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% called by start/start_link
init(Args) ->
  % Remove this when the SSL library is fixed (see #6068)
  error_logger:tty(false),
  ssl:start(),
  doit(Args#args{ctarget=Args#args.target, cport=Args#args.port, retrycnt=Args#args.retry}).

% start the process
doit(Args) ->
  debug(Args, io_lib:fwrite("~p on ~p", [Args#args.module, Args#args.ctarget])),
  % first let's call "connect" through "connecting" using a timeout of 0
  {ok, connecting, Args, 0}.

% get sslcheck opt
get_sslcheck([], {Acc, SSLcheck}) ->
  {Acc, SSLcheck};
get_sslcheck([{sslcheck, Val}|T], {Acc, _}) ->
  get_sslcheck(T, {Acc, Val});
get_sslcheck([H|T], {Acc, S}) ->
  get_sslcheck(T, {Acc++[H], S}).

get_ssl_opts(_Target, true) ->
  utils_ssl:get_opts_verify([]);
get_ssl_opts(Target, full) ->
  utils_ssl:get_opts_verify(Target);
get_ssl_opts(_Target, false) ->
  utils_ssl:get_opts_noverify().

% get privport opt
get_privports(true) ->
  [{port, rand:uniform(1024)}];
get_privports(_) ->
  [].

% provide the socket option
get_options(Args) ->
  {Opts, SSLcheck} = get_sslcheck(Args#args.fsmopts, {[], true}),
  ?COPTS ++ get_privports(Args#args.privports)
    ++ get_ssl_opts(Args#args.ctarget, SSLcheck)
    ++ Opts.

% State connecting is used to initiate the ssl connection
connecting(timeout, Data) ->
  Host = Data#args.ctarget, Port = Data#args.cport, Timeout = Data#args.timeout,
  case utils_fp:lookup(Host, Timeout, Data#args.checkwww) of
    {ok, Addr} ->
      try
        case ssl:connect(Addr, Port, get_options(Data), Timeout) of
          {ok, Socket} ->
            {next_state, callback, Data#args{socket=Socket,ipaddr=Addr}, 0};
          {error, {tls_alert, Reason}} ->
            gen_fsm:send_event(self(), {error, {tls_error, Reason}}),
            {next_state, connecting, Data};
          {error, Reason} ->
            gen_fsm:send_event(self(), {error, Reason}),
            {next_state, connecting, Data}
        end
      catch
        _:_ ->
          gen_fsm:send_event(self(), {error, unknown}),
          {next_state, connecting, Data}
      end;
    {error, Reason} ->
      gen_fsm:send_event(self(), {error, Reason}),
      {next_state, connecting, Data}
  end;
% called when connection is refused
connecting({error, econnrefused=Reason}, Data) ->
  {stop, normal, Data#args{result={{error, up}, Reason}}}; % RESULT
% called when connection is reset
connecting({error, econnreset=Reason}, Data) ->
  {stop, normal, Data#args{result={{error, up}, Reason}}}; % RESULT
% called when source port is already taken
connecting({error, tcp_eacces}, Data)
when Data#args.privports == true, Data#args.eaccess_retry < Data#args.eaccess_max ->
  {next_state, connecting, Data#args{eaccess_retry=Data#args.eaccess_retry+1}, 0};
% called when tls alert occurs (badcert, ...)
connecting({error, {tls_error=Type, R}}, Data) ->
  {stop, normal, Data#args{result={{error, up}, [Type, R]}}}; % RESULT
% called when connection failed
connecting({error, Reason}, Data) ->
  {stop, normal, Data#args{result={{error, unknown}, Reason}}}. % RESULT

receiving(timeout, Data) ->
  case ssl:recv(Data#args.socket, 0, Data#args.timeout) of
    {ok, Packet} ->
      handle_packet(Packet, Data);
    {error, Reason} ->
      {next_state, callback, Data#args{rcvreason=Reason}, 0}
  end.

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
  error_logger:tty(true),
  ok.

% flush_socket(Socket) ->
%   case ssl:recv(Socket, 0, 0) of
%     {error, _Reason} ->
%       ok;
%     {ok, _Result} ->
%       flush_socket(Socket)
%   end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% event handlers
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% called when a new packet is received
handle_packet(Packet, Data) ->
  case Data#args.nbpacket of
    infinity ->
      {next_state, receiving, Data#args{
        datarcv = <<(Data#args.datarcv)/binary, Packet/binary>>,
        packetrcv = Data#args.packetrcv + 1
        },
      0};
    1 -> % It is the last packet to receive
      {next_state, callback, Data#args{
        datarcv = <<(Data#args.datarcv)/binary, Packet/binary>>,
        nbpacket = 0,
        packetrcv = Data#args.packetrcv + 1
        },
      0};
    0 -> % If they didn't want any packet ?
      {stop, normal, Data#args{result={
        {error,up},[toomanypacketreceived, Packet]}}}; % RESULT
    _ -> % They are more packets (maybe)
      {next_state, receiving, Data#args{
        datarcv = <<(Data#args.datarcv)/binary, Packet/binary>>,
        nbpacket=Data#args.nbpacket - 1,
        packetrcv = Data#args.packetrcv + 1
        },
      0}
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% UNUSED event handlers
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
code_change(_Prev, State, Data, _Extra) ->
  {ok , State, Data}.
handle_sync_event(_Ev, _From, _State, Data) ->
  {stop, unexpectedSyncEvent, Data}.
handle_event(_Ev, _State, Data) ->
  {stop, unexpectedEvent, Data}.
handle_info({ssl_closed, _Socket}, _State, Data)  ->
  {stop, normal, Data};
handle_info(_Ev, _State, Data)  ->
  {stop, unexpectedEvent, Data}.

