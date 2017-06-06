%% utils for parsing http and handling redirection
%%
%% when redirections occurs, you still need to check
%% that the redirection does not point back to your
%% original target and page after some redirections
%% as no internal stack of redirections is kept in here
%%
%% type of result returned:
%%    {ok, {Code, Headermap, Body}}
%%          HTTP 200 received and a Map containing the header options as well
%%          as the body are returned
%%    {error, Data}:
%%          unable to parse http
%%    {redirect, {error, empty}, {Code, Headermap, Body}}
%%          Redirection found (3XX) but no value
%%          given
%%    {redirect, {error, cyclic}, {Code, Headermap, Body}}
%%          redirection (3XX) is cyclic
%%    {redirect, {error, Location}, {Code, Headermap, Body}}
%%          redirection error while parsing the location
%%    {redirect, {ok, {Host, Page}}, {Code, Headermap, Body}}
%%          redirection to Host and Page
%%    {redirect, {https, {Host, Page}}, {Code, Headermap, Body}}
%%          redirection HTTPs on Host and Page
%%    {http, {Code, Headermap, Body}}
%%          a HTTP code was received that is not 2XX or 3XX
%%    {other, {Code, Headermap, Body}}
%%          Something was received that didn't seem to be HTTP
%%

-module(utils_http).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-export([parse_http/3, parse_http/4]).

% parsing defines
-define(HTTP_OK, "2").
-define(HTTP_REDIRECT, "3").
-define(CRLF, "\r\n").
-define(LF, "\n").
-define(HDRFIELDSEP, ":").
-define(PAGE_SEP, "/").
-define(PAGE_RET, "..").
-define(HTTP_LOCATION, "location").

-record(rec, {
    code,
    page,
    host,
    headermap,
    header,
    body,
    dbg,
    protoline,
    payload
  }).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% parse an http response from host Host (the entry in the Host: field of the
% query) to page Page (for example "/" or "/readme.txt")
% if Dbginfo is set to {Target, Id, Debugval} then
% debug will be outputed if needed otherwise set it to {}
parse_http(Host, Page, Payload) ->
  parse_http(Host, Page, Payload, {}).
parse_http(Host, Page, Payload, DbgInfo) ->
  Resp = fix_crlf(Payload),
  case parse_response(Resp, []) of
    ["", Body] ->
      debug(DbgInfo, "this is no HTTP or no header found"),
      {other, {"", maps:new(), Body}};
    [Header, Body]  ->
      debug(DbgInfo, "HTTP parse successfully"),
      Rec = #rec{host=Host, page=Page, header=Header, body=Body, payload=Payload, dbg=DbgInfo},
      match_header(Rec, get_proto_code(Header, []))
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% matchers
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
match_header(Rec, {[], _}) ->
  {error, Rec#rec.payload};
match_header(Rec, {Protoline, HeaderFields}) ->
  debug(Rec#rec.dbg, io_lib:fwrite("HTTP response: ~p", [Protoline])),
  % get a map of the header
  Headermap = parse_header(HeaderFields, maps:new(), []),
  Nrec = Rec#rec{protoline=Protoline, headermap=Headermap},
  match_proto(Nrec).

match_proto(Rec) when length(Rec#rec.protoline) < 2 ->
  {other, {lists:concat(Rec#rec.protoline), Rec#rec.header, Rec#rec.body}};
match_proto(Rec) ->
  case validate_http_code(lists:nth(2, Rec#rec.protoline)) of
    {ok, ?HTTP_OK ++ _ = Code} ->
      % 2XX
      {ok, {Code, Rec#rec.headermap, Rec#rec.body}};
    {ok, ?HTTP_REDIRECT ++ _ = Code} ->
      % 3XX
      NRec = Rec#rec{code = Code},
      handle_redirect(NRec);
    {ok, Code} ->
      {http, {Code, Rec#rec.headermap, Rec#rec.body}};
    {error, _Code} ->
      % other stuff
      {other, {lists:concat(Rec#rec.protoline), Rec#rec.headermap, Rec#rec.body}}
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% handler
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% handle redirection
handle_redirect(Rec) ->
  Loc = maps:get(?HTTP_LOCATION, Rec#rec.headermap, ""),
  debug(Rec#rec.dbg, io_lib:fwrite("<redirection> Header: ~p", [Rec#rec.headermap])),
  {redirect, redirect_location(Loc, Rec),
    {Rec#rec.code, Rec#rec.headermap, Rec#rec.body}}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% debug
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
debug({}, _) ->
  ok;
debug({Target, Id, Debugval}, Msg) ->
  utils:debug(fpmodules, Msg,
    {Target, Id}, Debugval).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% parsing
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% parse each header field and return
% a list with key, value
parse_hdr_field(?HDRFIELDSEP ++ Rest, Acc) ->
  [string:strip(lists:reverse(Acc)), string:strip(Rest)];
parse_hdr_field([H|T], Acc) ->
  parse_hdr_field(T, [H|Acc]);
parse_hdr_field([], Acc) ->
  [lists:reverse(Acc), ""].

% this allows to retrieve the http code
% line from the header
get_proto_code([], _) ->
  {[], []};
get_proto_code(?CRLF ++ Rest, Acc) ->
  {string:tokens(lists:reverse(Acc), " "), Rest};
get_proto_code([H|T], Acc) ->
  get_proto_code(T, [H|Acc]).

% parse the header and isolate each
% option to process
% returns a map of the options
parse_header(?CRLF ++ [], Map, Acc) ->
  [H, T] = parse_hdr_field(lists:reverse(Acc), []),
  maps:put(normalize_key(H), T, Map);
parse_header(?CRLF ++ Rest, Map, Acc) ->
  [H, T] = parse_hdr_field(lists:reverse(Acc), []),
  Nmap = maps:put(normalize_key(H), T, Map),
  parse_header(Rest, Nmap, []);
parse_header([H|T], Map, Acc) ->
  parse_header(T, Map, [H|Acc]);
parse_header([], Map, _Agg) ->
  Map.

% only parse header/body if we have HTTP code
parse_response("HTTP" ++ _ = Res, Acc) ->
  sub_parse_response(Res, Acc);
parse_response(Else, _Acc) ->
  ["", Else].

% parse the response and separate the
% header and the body separated by two CRLF
sub_parse_response(?CRLF ++ ?CRLF ++ Rest, Acc) ->
  [lists:reverse(Acc)++?CRLF, Rest];
sub_parse_response([H|T], Acc) ->
  sub_parse_response(T, [H|Acc]);
sub_parse_response([], _Acc) ->
  ["", ""].

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% utils
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% handles @&#($* not following RFC
fix_crlf(Data) ->
  case string:str(Data, ?CRLF) of
    0 ->
      re:replace(Data, ?LF, ?CRLF, [{return,list},global]);
    _ ->
      Data
  end.

% loose validate HTTP code
validate_http_code(Code) ->
  try
    case list_to_integer(Code) >= 100 andalso list_to_integer(Code) < 600 of
      true ->
        {ok, Code};
      false ->
        {error, Code}
    end
  catch
    _:_ ->
      {error, Code}
  end.

% normalize header option
normalize_key(Key) ->
  string:strip(string:to_lower(Key)).

%% RFC2616 (https://tools.ietf.org/html/rfc2616#section-14.30) specifies
%% that the location should be an absolute URI.
%% however since 2014 the new RFC (https://tools.ietf.org/html/rfc7231#section-7.1.2)
%% allows relative and absolute URI
%% relative-path definition is https://tools.ietf.org/html/rfc3986#section-4.2
redirect_location([], _Rec) ->
  % empty redirect
  {error, empty};
redirect_location("http://" = Loc, _Rec) ->
  {error, Loc};
redirect_location("//" ++ Redir, Rec) ->
  % example:
  %   redirect: //<domain>/
  redirect_location("http://" ++ Redir, Rec);
redirect_location("/" ++ _ = Page, Rec) ->
  % example:
  %   redirect: /frontend/../it/home"
  redirect_follow(Rec#rec.host, Rec#rec.page, Rec#rec.host, eval_redirect_page(Page, Rec#rec.dbg), Rec#rec.dbg);
redirect_location("../" ++ _ = Page, Rec) ->
  % example:
  %   redirect: ../home
  %   redirect: ../<domain>/asplogin.asp
  %   redirect: ../staff_online/staff/main/stafflogin.asp?action=start
  redirect_follow(Rec#rec.host, Rec#rec.page, Rec#rec.host,
    eval_redirect_page(Rec#rec.page ++ Page, Rec#rec.dbg), Rec#rec.dbg);
redirect_location("http://" ++ Field, Rec) ->
  % now split host and page
  Ends = string:right(Field, 1) == ?PAGE_SEP,
  Fields = string:tokens(Field, ?PAGE_SEP),
  case Fields of
    [] ->
      {error, empty};
    F ->
      Host = string:strip(hd(F), right, $.),
      Page = ?PAGE_SEP ++ string:join(tl(F), ?PAGE_SEP),
      NewPage = complete_page(Page, Ends),
      redirect_follow(Rec#rec.host, Rec#rec.page, Host, NewPage, Rec#rec.dbg)
  end;
redirect_location("https://" ++ Field, _Rec) ->
  % now split host and page
  Ends = string:right(Field, 1) == ?PAGE_SEP,
  Fields = string:tokens(Field, ?PAGE_SEP),
  case Fields of
    [] ->
      {error, empty};
    F ->
      Host = string:strip(hd(F), right, $.),
      Page = ?PAGE_SEP ++ string:join(tl(F), ?PAGE_SEP),
      NewPage = complete_page(Page, Ends),
      {https, {Host, NewPage}}
  end;
redirect_location(Location, Rec) ->
  % complete current page with redirect
  NewPage = eval_redirect_page(Rec#rec.page ++ ?PAGE_SEP ++ Location, Rec#rec.dbg),
  redirect_follow(Rec#rec.host, Rec#rec.page, Rec#rec.host, NewPage, Rec#rec.dbg).

redirect_follow(Curhost, Curpage, NewHost, NewPage, Dbg) ->
  case (NewHost == Curhost andalso NewPage == Curpage) of
    true ->
      debug(Dbg, io_lib:fwrite("cyclic !! ~p/~p => ~p/~p", [Curhost, Curpage, NewHost, NewPage])),
      {error, cyclic};
    false ->
      debug(Dbg, io_lib:fwrite("redir ok to ~p ~p", [NewHost, NewPage])),
      {ok, {NewHost, NewPage}}
  end.

complete_page(Page, AddSep) ->
  Ispresent = string:right(Page, 1) == ?PAGE_SEP,
  case AddSep of
    true ->
      case Ispresent of
        true ->
          Page;
        false ->
          Page ++ ?PAGE_SEP
      end;
    false ->
      Page
  end.

% returns absolute path from relative path
eval_redirect_list([[]|T], Agg) ->
  eval_redirect_list(T, Agg);
eval_redirect_list([?PAGE_RET|T], []) ->
  eval_redirect_list(T, []);
eval_redirect_list([?PAGE_RET|T], Agg) ->
  eval_redirect_list(T, tl(Agg));
eval_redirect_list([H|T], Agg) ->
  eval_redirect_list(T, [H|Agg]);
eval_redirect_list([], []) ->
  % no redirection, points to same place
  [""];
eval_redirect_list([], Agg) ->
  case string:str(hd(Agg), ".") of
    0 ->
      lists:reverse([[]|Agg]);
    _ ->
      lists:reverse(Agg)
  end.

eval_redirect_page(?PAGE_SEP, _Dbg) ->
  ?PAGE_SEP;
eval_redirect_page(?PAGE_SEP ++ ?PAGE_SEP ++ Rest, Dbg) ->
  eval_redirect_page(?PAGE_SEP ++ Rest, Dbg);
eval_redirect_page(Page, Dbg) ->
  debug(Dbg, io_lib:fwrite("redirect to ~p", [Page])),
  case string:str(Page, ?PAGE_RET) of
    0 ->
      Page;
    _ ->
      debug(Dbg, io_lib:fwrite("eval redirect being: ~p", [string:tokens(Page, ?PAGE_SEP)])),
      Ends = string:right(Page, 1) == ?PAGE_SEP,
      Res = eval_redirect_list(string:tokens(Page, ?PAGE_SEP), []),
      ?PAGE_SEP ++ string:join(Res, ?PAGE_SEP) ++ case Ends of true -> ?PAGE_SEP; _ -> "" end
  end.

