%%% HTTPS fingerprint module to retrieve x509 certificate
%%%
%%% Output:
%%% Certificate in PEM
%%%

-module(fp_https_certif).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").
-behavior(fp_module).

-include("../includes/args.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([callback_next_step/1]).
-export([get_default_args/0]).
-export([get_description/0]).
-export([get_arguments/0]).

-define(TIMEOUT, 3000). %% milli-seconds
-define(PORT, 443).     %% HTTPS port
-define(TYPE, ssl).     %% transport type
%% define SSL options
-define(SSLOPTS, [{sslcheck,false}]).
%-define(SSLOPTS, [{sslcheck,false}, {versions,['tlsv1.2']}]).
%-define(SSLOPTS, [{sslcheck,false}, {versions,['tlsv1.2']}, {server_name_indication, disable}]).
%-define(SSLOPTS, [{sslcheck,false}, {server_name_indication, disable}]).
-define(MAXPKT, 5).
-define(UALEN, 2).      %% user-agent length
-define(PAGE, "/").
-define(DESCRIPTION, "SSL/443: HTTPS certificate graber").
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
  % no packet received
  debug(Args, "no packet received"),
  {result, {{error, up}, timeout}};
callback_next_step(Args) ->
  % parse the result
  debug(Args, "packet received"),
  get_results(Args).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% response parser
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% parse cert and return the results
get_results(Args) ->
  case utils_ssl:get_certif(Args#args.socket) of
    {ok, Cert} ->
      {result, {{ok, result}, [Args#args.ipaddr, Cert]}};
    {error, Reason} ->
      {result, {{error, up}, Reason}}
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% HTTPS packet request forger
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% returns HTTPS payload
randua(0, Acc) ->
  Acc;
randua(N, Acc) ->
  randua(N - 1, [rand:uniform(26) + 96 | Acc]).

%% return the payload
payload(Host) ->
  Ua = randua(?UALEN, ""),
  Args = ["GET ", ?PAGE, " HTTP/1.1", "\r\n", "Host: ", Host, "\r\n",
    "User-Agent: ", Ua, "\r\n",
    "Accept: */*", "\r\n",
    "Language: en", "\r\n\r\n"],
  lists:concat(Args).

%% return the payload with the target
get_payload(Addr={_,_,_,_}) ->
  payload(inet:ntoa(Addr));
get_payload(Host) ->
  payload(Host).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% debug
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% send debug
debug(Args, Msg) ->
  utils:debug(fpmodules, Msg,
    {Args#args.target, Args#args.id}, Args#args.debugval).
