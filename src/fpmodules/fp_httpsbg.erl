%%% HTTPS banner grabing module
%%% returns the Server entry in the response's header
%%%
%%% Output:
%%%   Server entry value in HTTP header
%%%

-module(fp_httpsbg).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").
-behavior(fp_module).

-include("../includes/args.hrl").

-export([callback_next_step/1]).
-export([get_default_args/0]).
-export([get_description/0]).
-export([get_arguments/0]).

-define(TIMEOUT, 3000). % milli-seconds
-define(PORT, 443). % HTTPS port
-define(TYPE, ssl). % transport type
-define(MAXPKT, 1).
-define(UALEN, 2). % user-agent length
%-define(SSLOPTS, [{sslcheck,false}, {versions,['tlsv1.2']}, {server_name_indication, disable}]).
%-define(SSLOPTS, [{sslcheck,false}, {versions,['tlsv1.2']}]).
-define(SSLOPTS, [{sslcheck,false}]).
-define(PAGE, "/").
-define(HDRKEY, "server").
-define(DESCRIPTION, "SSL/443: HTTPS Server header identification").
-define(ARGUMENTS, []).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% public API to get {port, timeout}
get_default_args() ->
  #args{module=?MODULE, type=?TYPE, port=?PORT,
    timeout=?TIMEOUT, fsmopts=?SSLOPTS, maxpkt=?MAXPKT}.

get_description() ->
  ?DESCRIPTION.

get_arguments() ->
  ?ARGUMENTS.

callback_next_step(Args) when Args#args.moddata == undefined ->
  % first packet
  {continue, Args#args.maxpkt, get_payload(Args#args.target), true};
callback_next_step(Args) when Args#args.packetrcv < 1 ->
  debug(Args, "no packet received"),
  {result, {{error, up}, timeout}};
callback_next_step(Args) ->
  debug(Args, "packet received"),
  parse_payload(Args, binary_to_list(Args#args.datarcv)).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% debug
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% send debug
debug(Args, Msg) ->
  utils:debug(fpmodules, Msg,
    {Args#args.target, Args#args.id}, Args#args.debugval).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% HTTPS packet request forger
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% returns HTTPS payload
randua(0, Acc) ->
  Acc;
randua(N, Acc) ->
  randua(N - 1, [rand:uniform(26) + 96 | Acc]).

payload(Host) ->
  Ua = randua(?UALEN, ""),
  Args = ["GET ", ?PAGE, " HTTP/1.1", "\r\n", "Host: ", Host, "\r\n",
    "User-Agent: ", Ua, "\r\n",
    "Accept: */*", "\r\n",
    "Language: en", "\r\n\r\n"],
  lists:concat(Args).

get_payload(Addr={_,_,_,_}) ->
  payload(inet:ntoa(Addr));
get_payload(Host) ->
  payload(Host).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%% HTTPS response parser
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% parse http response
parse_payload(Args, Response) ->
  case utils_http:parse_http(Args#args.target, ?PAGE, Response,
    {Args#args.target, Args#args.id, Args#args.debugval}) of
    {error, _} ->
      % error while parsing response
      {result, {{error, up}, unexpected_data}};
    {redirect, _, {_Code, Header, _Body}} ->
      {result, {{ok, result}, [maps:get(?HDRKEY, Header, "")]}};
    {ok, {_Code, Header, _Body}} ->
      {result, {{ok, result}, [maps:get(?HDRKEY, Header, "")]}};
    {http, {_Code, Header, _Body}} ->
      {result, {{ok, result}, [maps:get(?HDRKEY, Header, "")]}};
    {other, {_Code, _Header, _Body}} ->
      {result, {{error, up}, unexpected_data}}
  end.

