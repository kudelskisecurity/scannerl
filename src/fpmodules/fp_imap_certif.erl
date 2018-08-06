%%% IMAP STARTTLS certificate graber
%%%
%%% Output:
%%% ip and certificate in pem
%%%
%%% https://tools.ietf.org/html/rfc2595
%%%

-module(fp_imap_certif).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").
-behavior(fp_module).

-include("../includes/args.hrl").

-export([callback_next_step/1]).
-export([get_default_args/0]).
-export([get_description/0]).
-export([get_arguments/0]).

-define(TIMEOUT, 6000). % milli-seconds
-define(PORT, 143).
-define(TYPE, tcp).
-define(MAXPKT, 1).
-define(STARTTLS, "STARTTLS").
-define(OK, "OK").
-define(DESCRIPTION, "TCP/143: IMAP STARTTLS certificate graber").
-define(ARGUMENTS, []).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% public API to get {port, timeout}
get_default_args() ->
  #args{module=?MODULE, type=?TYPE, port=?PORT,
    timeout=?TIMEOUT, maxpkt=?MAXPKT}.

get_description() ->
  ?DESCRIPTION.

get_arguments() ->
  ?ARGUMENTS.

callback_next_step(Args) when Args#args.moddata == undefined ->
  % first packet
  debug(Args, "sending empty payload"),
  {continue, Args#args.maxpkt, empty_payload(), first};
callback_next_step(Args) when Args#args.packetrcv < 1 ->
  debug(Args, "no packet received"),
  {result, {{error, up}, timeout}};
callback_next_step(Args) when Args#args.moddata == first ->
  % first response
  debug(Args, io_lib:fwrite("first packet received: ~p", [Args#args.datarcv])),
  case supports_starttls(Args#args.datarcv) of
    true ->
      debug(Args, "sending STARTTLS"),
      {continue, Args#args.maxpkt, starttls(), second};
    false ->
      debug(Args, "server is not ok"),
      {result, {{error,up}, unexpected_data}}
  end;
callback_next_step(Args) when Args#args.moddata == second ->
  %% second response
  debug(Args, io_lib:fwrite("starttls response received: ~p", [Args#args.datarcv])),
  case isok(Args#args.datarcv) of
    true ->
      upgrade(Args);
    false ->
      {result, {{error,up}, no_starttls}}
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% payloads
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% empty payload since server must communicate first
empty_payload() ->
  "".

%% starttls payload
starttls() ->
  lists:concat([randstring(1, []), " ", ?STARTTLS, "\r\n"]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% parser
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% is server ok
isok(Payload) ->
  Pld = binary_to_list(Payload),
  string:str(Pld, ?OK) /= 0.


%% upgrade connection with ssl
upgrade(Args) ->
  debug(Args, "upgrade connection with SSL/TLS"),
  case utils_ssl:upgrade_socket(Args#args.socket, [], ?TIMEOUT) of
    {ok, TLSSocket} ->
      case utils_ssl:get_certif(TLSSocket) of
        {ok, Cert} ->
          ssl:close(TLSSocket),
          {result, {{ok,result}, [Args#args.ipaddr, Cert]}};
        {error, Reason} ->
          ssl:close(TLSSocket),
          {result, {{error, up}, Reason}}
      end;
    {error, Reason} ->
      {result, {{error,up}, Reason}}
  end.

%% is starttls an option ?
supports_starttls(Payload) ->
  String = binary_to_list(Payload),
  string:str(String, ?STARTTLS) /= 0.

%% returns a random string of length N
randstring(0, Acc) ->
  Acc;
randstring(N, Acc) ->
  randstring(N - 1, [rand:uniform(26) + 96 | Acc]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% debug
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% send debug
debug(Args, Msg) ->
  utils:debug(fpmodules, Msg,
    {Args#args.target, Args#args.id}, Args#args.debugval).
