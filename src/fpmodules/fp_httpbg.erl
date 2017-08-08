%%% HTTP banner grabing module
%%% returns the Server entry in the response's header
%%%
%%% Output:
%%%   Server entry value in HTTP header
%%%

-module(fp_httpbg).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").
-author("David Rossier - david.rossier@kudelskisecurity.com").

-behavior(fp_module).

-include("../includes/args.hrl").

-export([callback_next_step/1]).
-export([get_default_args/0]).
-export([get_description/0]).
-export([get_arguments/0]).

-define(TIMEOUT, 3000). % milli-seconds
-define(PORT, 80). % HTTP port
-define(TYPE, tcp). % transport type
-define(UALEN, 2). % user-agent length
-define(HDRKEY, "server").
-define(MAXPKT, 1).
-define(MAXREDIRECT, 3).
-define(MAXREDIR, maxredirection).
-define(DESCRIPTION, "TCP/80: HTTP Server header identification").
-define(ARGUMENTS, ["[true|false] follow redirection [Default:false]"]).

%% our record for this fingerprint
-record(sd, {
    follow = false,
    host,
    requery = false,
    redircnt = 0,
    page="/"
  }).

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

% construct internal record with arguments
get_internal_args(Arguments) when Arguments == ["true"] ->
  #sd{follow=true};
get_internal_args(_Arguments) ->
  #sd{}.

% callback
callback_next_step(Args) when Args#args.moddata == undefined ->
  % first packet
  Sd = get_internal_args(Args#args.arguments),
  debug(Args, io_lib:fwrite("query ~p ~p (follow:~p)", [Args#args.target, Sd#sd.page, Sd#sd.follow])),
  {continue, Args#args.maxpkt, get_payload(Args#args.target, Sd#sd.page), Sd#sd{host=Args#args.target}};
callback_next_step(Args) when Args#args.moddata#sd.requery == true ->
  % first packet
  Sd = Args#args.moddata,
  debug(Args, io_lib:fwrite("REquery ~p ~p", [Sd#sd.host, Sd#sd.page])),
  {continue, Args#args.maxpkt, get_payload(Sd#sd.host, Sd#sd.page), Sd#sd{requery=false}};
callback_next_step(Args) when Args#args.packetrcv < 1 ->
  % no packet received
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
%%% HTTP packet request forger
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% returns HTTP payload
randua(0, Acc) ->
  Acc;
randua(N, Acc) ->
  randua(N - 1, [rand:uniform(26) + 96 | Acc]).

payload(Host, Page) ->
  Ua = randua(?UALEN, ""),
  Args = ["GET ", Page, " HTTP/1.1", "\r\n", "Host: ", Host, "\r\n",
    "User-Agent: ", Ua, "\r\n",
    "Accept: */*", "\r\n",
    "Language: en", "\r\n\r\n"],
  lists:concat(Args).

get_payload(Addr={_,_,_,_}, Page) ->
  payload(inet:ntoa(Addr), Page);
get_payload(Host, Page) ->
  payload(Host, Page).
%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%% HTTP response parser
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% parse http response
parse_payload(Args, Response) ->
  Sd = Args#args.moddata,
  case utils_http:parse_http(Sd#sd.host, Sd#sd.page, Response,
    {Args#args.target, Args#args.id, Args#args.debugval}) of
    {error, _Data} ->
      % error while parsing response
      {result,{{error, up}, unexpected_data}}; % RESULT
    {redirect, {ok, {Host, Page}}, {_Code, Header, _Body}} ->
      case Args#args.moddata#sd.follow of
        true ->
          case maps:find(?HDRKEY, Header) of
            {ok, Value} ->
              debug(Args, io_lib:fwrite("Server found in header: ~p", [Header])),
              {result, {{ok, result}, [Value]}};
            error ->
              % follow redirection
              debug(Args, "httpbg is following redirection ..."),
              httpredirect(Args, Args#args.target, Host, Page, Sd)
          end;
        false ->
          % do not follow redirection
          {result, {{ok, result}, [maps:get(?HDRKEY, Header, "")]}}
      end;
    {redirect, {https, _}, {_Code, Header, _Body}} ->
      debug(Args, "Redirect error https"),
      {result, {{ok, result}, [maps:get(?HDRKEY, Header, "")]}};
    {redirect, {error, Reason}, {_Code, Header, _Body}} ->
      debug(Args, io_lib:fwrite("Redirect error: ~p", [Reason])),
      {result, {{ok, result}, [maps:get(?HDRKEY, Header, "")]}};
    {ok, {_Code, Header, _Body}} ->
      {result, {{ok, result}, [maps:get(?HDRKEY, Header, "")]}};
    {http, {_Code, Header, _Body}} ->
      {result, {{ok, result}, [maps:get(?HDRKEY, Header, "")]}};
    {other, {_Code, _Header, _Body}} ->
      {result,{{error, up}, unexpected_data}}
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% redirection
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
httpredirect(Data, Oritgt, Host, Page, Sd)
when Host == Oritgt andalso (Page == Sd#sd.page orelse Page == "/") ->
  debug(Data, io_lib:fwrite("cyclic redirect to ~p -> ~p", [Host, Page])),
  {result,{{error, up}, redir_cyclic}}; % RESULT
httpredirect(Data, _, Host, Page, Sd) when Sd#sd.redircnt < ?MAXREDIRECT ->
  Newsd = Sd#sd{page=Page, host=Host, redircnt=Sd#sd.redircnt+1, requery=true},
  debug(Data, io_lib:fwrite("redirect to ~p -> ~p", [Host, Page])),
  {restart, {Host, undefined}, Newsd};
httpredirect(Data, _, _Host, _Page, _Md) ->
  debug(Data, "max redirection reached"),
  {result,{{error, up}, max_redirect}}.

