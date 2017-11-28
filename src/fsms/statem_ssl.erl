%%% SSL statem
%%%
%%%
%%% specific option can be set to control how
%%% the remote certificate is checked:
%%%   {sslcheck, true}: check the certificate validity
%%%   {sslcheck, full}: the above plus the domain check
%%%   {sslcheck, false}: disable ssl checking
%%%   {sslcheck, retry}: full ssl checking and retry with "false" if error
%%%   {sni, disable}: disable sni
%%%   {sni, enable}: enable sni
%%%   {sni, retry}: enable sni and retry without if error
%%% defaults is erlang's defaults (http://erlang.org/doc/man/ssl.html)
%%%

-module(statem_ssl).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").
-behavior(gen_statem).

-include("../includes/args.hrl").

% gen_statem imports
-export([start_link/1, start/1]).
-export([init/1, terminate/3, code_change/4]).
-export([callback_mode/0]).

% callbacks
-export([connecting/3, callback/3, receiving/3]).

% see http://erlang.org/doc/man/inet.html#setopts-2
-define(COPTS, [binary, {packet, 0}, inet, {recbuf, 65536}, {active, false}, {reuseaddr, true}]).

% this records allows to use "retry"
% with sslcheck and sni
-record(retry, {
          sni = false,
          sslcheck = false
         }
       ).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% gen_statem specific
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% called by start/start_link
init(Args) ->
  error_logger:tty(false),
  ssl:start(),
  doit(Args#args{ctarget=Args#args.target, cport=Args#args.port, retrycnt=Args#args.retry}).

%% start the process
doit(Args) ->
  debug(Args, io_lib:fwrite("~p on ~p", [Args#args.module, Args#args.ctarget])),
  % first let's call "connect" through "connecting" using a timeout of 0
  {ok, connecting, Args, 0}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% fsm callbacks
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% called for sending first packet
callback(timeout, _EventContent, Data) when Data#args.retrycnt > 0 andalso Data#args.packetrcv == 0
    andalso Data#args.payload /= << >>  ->
  send_data(Data#args{retrycnt=Data#args.retrycnt-1});
%% called for sending additional packet when needed
callback(timeout, _EventContent, Data) ->
  debug(Data, "fsm timeout"),
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
      {stop, normal, Data#args{result=Result}}
  end;
%% called when ssl socket is abruptly closed
callback(cast, {ssl_closed, _Socket}, Data)  ->
  debug(Data, "fsm ssl_closed error"),
  {stop, normal, Data#args{result={{error, up}, ssl_closed}}};
%% called when tls_alert
callback(cast, {ssl_error, _Socket, {tls_alert, Reason}}, Data)  ->
  debug(Data, io_lib:fwrite("fsm tls_alert: ~p", [Reason])),
  {stop, normal, Data#args{result={{error, up}, [tls_alert, Reason]}}};
%% tls error
callback(cast, {tls_error, _Socket, {tls_error, Reason}}, Data)  ->
  debug(Data, io_lib:fwrite("fsm tls_error: ~p", [Reason])),
  ssl:close(Data#args.socket),
  {stop, normal, Data#args{result={{error, up}, Reason}}};
%% other errors
callback(cast, {error, Reason}, Data) ->
  debug(Data, io_lib:fwrite("fsm error: ~p", [Reason])),
  ssl:close(Data#args.socket),
  {stop, normal, Data#args{result={{error, up}, Reason}}};
callback(Event, EventContent, Data)  ->
  debug(Data, io_lib:fwrite("fsm unexpected event: ~p - ~p", [Event, EventContent])),
  {stop, normal, Data#args{result={{error, unknown}, [unexpected_event, Event, EventContent, Data]}}}.

%% State connecting is used to initiate the ssl connection
connecting(timeout, _, Data) ->
  Host = Data#args.ctarget, Port = Data#args.cport, Timeout = Data#args.timeout,
  case utils_fp:lookup(Host, Timeout, Data#args.checkwww) of
    {ok, Addr} ->
      try
        {Opts, Retry} = get_options(Data),
        case ssl:connect(Addr, Port, Opts, Timeout) of
          {ok, Socket} ->
            {next_state, callback, Data#args{socket=Socket,ipaddr=Addr}, 0};
          {error, {tls_alert, Reason}} when Reason =:= "bad certificate";
                                            Reason =:= "certificate expired";
                                            Reason =:= "unknown ca";
                                            Reason =:= "handshake failure" ->
            % sslcheck retry
            case Retry#retry.sslcheck of
              true ->
                debug(Data, io_lib:fwrite("socket retry sslcheck error tls_alert: ~p", [Reason])),
                Nopts = utils:replace_in_list_of_tuple(Data#args.fsmopts, sslcheck, false),
                gen_statem:cast(self(), restart),
                {next_state, connecting, Data#args{fsmopts=Nopts}};
              false ->
                % sni retry
                case Retry#retry.sni and Reason =:= "handshake failure" of
                  true ->
                    % retry without sni
                    % by calling callback with restart
                    debug(Data, io_lib:fwrite("socket retry sni error tls_alert: ~p", [Reason])),
                    Nopts = utils:replace_in_list_of_tuple(Data#args.fsmopts, sni, disable),
                    gen_statem:cast(self(), restart),
                    {next_state, connecting, Data#args{fsmopts=Nopts}};
                  false ->
                    debug(Data, io_lib:fwrite("socket error tls_alert: ~p", [Reason])),
                    gen_statem:cast(self(), {error, {tls_error, Reason}}),
                    {next_state, connecting, Data}
                end
            end;
          {error, {tls_alert, Reason}} ->
            % any other tls error
            debug(Data, io_lib:fwrite("socket error tls_alert: ~p", [Reason])),
            gen_statem:cast(self(), {error, {tls_error, Reason}}),
            {next_state, connecting, Data};
          {error, Reason} ->
            % socket error
            debug(Data, io_lib:fwrite("socket error: ~p", [Reason])),
            gen_statem:cast(self(), {error, Reason}),
            {next_state, connecting, Data}
        end
      catch
        _:_ ->
          gen_statem:cast(self(), {error, unknown}),
          {next_state, connecting, Data}
      end;
    {error, Reason} ->
      gen_statem:cast(self(), {error, Reason}),
      {next_state, connecting, Data}
  end;
%% called when connection is refused
connecting(cast, {error, econnrefused=Reason}, Data) ->
  {stop, normal, Data#args{result={{error, up}, Reason}}};
%% called when connection is reset
connecting(cast, {error, econnreset=Reason}, Data) ->
  {stop, normal, Data#args{result={{error, up}, Reason}}};
%% called when source port is already taken
connecting(cast, {error, tcp_eacces}, Data)
when Data#args.privports == true, Data#args.eaccess_retry < Data#args.eaccess_max ->
  {next_state, connecting, Data#args{eaccess_retry=Data#args.eaccess_retry+1}, 0};
%% called when tls alert occurs (badcert, ...)
connecting(cast, {error, {tls_error=Type, R}}, Data) ->
  {stop, normal, Data#args{result={{error, up}, [Type, R]}}};
%% called when need to restart
connecting(cast, restart, Data) ->
  {next_state, connecting, Data, 0};
%% called when connection failed
connecting(cast, {error, Reason}, Data) ->
  {stop, normal, Data#args{result={{error, unknown}, Reason}}};
%% called when remote closes the socket
connecting(info, {ssl_closed=Reason, _}, Data) ->
  {stop, normal, Data#args{result={{error, up}, Reason}}}.

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
  {Opts, Retry} = parse_ssl_opts(Args#args.fsmopts, Args#args.ctarget, [], #retry{}),
  Ret = ?COPTS ++ get_privports(Args#args.privports) ++ Opts,
  {Ret, Retry}.

%% send data
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

%% receive data
receiving(timeout, _EventContent, Data) ->
  try
    case ssl:recv(Data#args.socket, 0, Data#args.timeout) of
      {ok, Packet} ->
        handle_packet(Packet, Data);
      {error, Reason} ->
        {next_state, callback, Data#args{rcvreason=Reason}, 0}
    end
  catch
    _Err:_Exc ->
      gen_statem:cast(self(), {error, ssl_proto_error}),
      {next_state, callback, Data#args{rcvreason=ssl_proto_error}, 0}
  end.

% parse options
parse_ssl_opts([], _Tgt, Acc, Retry) ->
  % no more option
  {Acc, Retry};
parse_ssl_opts([{sslcheck, true}|T], Tgt, Acc, Retry) ->
  % sslcheck true
  Opt = utils_ssl:get_opts_verify([]),
  parse_ssl_opts(T, Tgt, Acc ++ Opt, Retry);
parse_ssl_opts([{sslcheck, false}|T], Tgt, Acc, Retry) ->
  % sslcheck false
  Opt = utils_ssl:get_opts_noverify(),
  parse_ssl_opts(T, Tgt, Acc ++ Opt, Retry);
parse_ssl_opts([{sslcheck, full}|T], Tgt, Acc, Retry) ->
  % sslcheck full
  Opt = utils_ssl:get_opts_verify(Tgt),
  parse_ssl_opts(T, Tgt, Acc ++ Opt, Retry);
parse_ssl_opts([{sslcheck, retry}|T], Tgt, Acc, Retry) ->
  % sslcheck full & retry
  Opt = utils_ssl:get_opts_verify(Tgt),
  parse_ssl_opts(T, Tgt, Acc ++ Opt, Retry#retry{sslcheck=true});
parse_ssl_opts([{sni, enable}|T], Tgt, Acc, Retry) ->
  % sni enable
  Opt = [{server_name_indication, utils:tgt_to_string(Tgt)}],
  parse_ssl_opts(T, Tgt, Acc ++ Opt, Retry);
parse_ssl_opts([{sni, disable}|T], Tgt, Acc, Retry) ->
  % sni disable
  Opt = [{server_name_indication, disable}],
  parse_ssl_opts(T, Tgt, Acc ++ Opt, Retry);
parse_ssl_opts([{sni, retry}|T], Tgt, Acc, Retry) ->
  % sni enable & retry
  Opt = [{server_name_indication, utils:tgt_to_string(Tgt)}],
  parse_ssl_opts(T, Tgt, Acc ++ Opt, Retry#retry{sni=true});
parse_ssl_opts([H|T], Tgt, Acc, Retry) ->
  % no match -> add as is
  parse_ssl_opts(T, Tgt, Acc ++ H, Retry).

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
        {error,up},[toomanypacketreceived, Packet]}}};
    _ -> % They are more packets (maybe)
      {next_state, receiving, Data#args{
        datarcv = <<(Data#args.datarcv)/binary, Packet/binary>>,
        nbpacket=Data#args.nbpacket - 1,
        packetrcv = Data#args.packetrcv + 1
        },
      0}
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% helper for the fsm
%% gen_statem http://erlang.org/doc/man/gen_statem.html
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% this is when there's no supervisor Args is an #args record
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
  error_logger:tty(true),
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

