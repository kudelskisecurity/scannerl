%% message server used to communicate with the master
%% from the cli. This is a workaround around the fact
%% erlang does not natively handle the linux signals.
%%
%% currently recognized message:
%%  - progress: display the progress
%%  - abort: abort the scan
%%
%% example:
%%    echo -n "abort" | nc -4u -q1 127.0.0.1 57005
%%

-module(utils_msgserver).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-export([listen_udp/2]).
-export([stop_udp/1]).

-define(LOCALHOST, {127,0,0,1}).
%-define(UDP_PORT, 57005). % 0xdead
-define(MAX_PORT, 65535).
-define(RETRY, 3).

-define(UDP_OPT, [list, inet]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
listen_udp(Parent, Port) ->
  listen_udp(?LOCALHOST, Port, Parent).

% returns either ok or {error, Reason}
stop_udp(Port) when Port > ?MAX_PORT ->
  ok;
stop_udp(Port) ->
  case gen_udp:open(0, ?UDP_OPT) of
    {ok, Socket} ->
      gen_udp:send(Socket, ?LOCALHOST, Port, "stop"),
      gen_udp:close(Socket);
    {error, Reason} ->
      {error, Reason}
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% UDP utils
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
listen_udp(_Ip, Port, _Parent) when Port > ?MAX_PORT ->
  ok;
listen_udp(Ip, Port, Parent) ->
  try_to_listen(Ip, Port, Parent, ?RETRY, "").

try_to_listen(_Ip, Port, Parent, 0, Reason) ->
  send_error(Parent, "UDP", Port, Reason);
try_to_listen(Ip, Port, Parent, Cnt, _Reason) ->
  Opt = ?UDP_OPT ++ [{ip, Ip}],
  case gen_udp:open(Port, Opt) of
    {ok, Socket} ->
      send_ok(Parent, "UDP", Ip, Port),
      udp_loop(Socket, Parent);
    {error, NReason} ->
      try_to_listen(Ip, Port, Parent, Cnt-1, NReason)
  end.

udp_loop(Socket, Parent) ->
  receive
    {udp, Socket, _Host, _Port, Message} ->
      case parse_message(Parent, Message) of
        stop ->
          gen_udp:close(Socket),
          ok;
        continue ->
          udp_loop(Socket, Parent)
      end
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% utils
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
parse_message(_Parent, Message) when Message == "stop" ->
  % send by master to stop listening
  stop;
parse_message(Parent, Message) when Message == "abort" ->
  % send to abort the scan
  send_message(Parent, Message),
  continue;
parse_message(Parent, Message) when Message == "progress" ->
  % send to abort the scan
  send_message(Parent, Message),
  continue;
parse_message(_Parent, _Message) ->
  % ignore message
  continue.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% messaging
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
send_error(Parent, Proto, Port, Reason) ->
  Parent ! {message, {error, Proto, Port, Reason}}.

send_ok(Parent, Protocol, Ip, Port) ->
  Parent ! {message, {ok, Protocol, inet_parse:ntoa(Ip), Port}}.

send_message(Parent, Message) ->
  Parent ! {message, {message, Message}}.

