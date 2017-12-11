%%% FOX helper
%%%

-module(utils_fox).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-export([parse_min/1, parse_full/1, forge_min_hello/0]).

-define(CANARY, "fox").
-define(CANARY_HTTP, "HTTP").
-define(CANARY_SSH, "SSH").
-define(LINE_SEP, '\n').
-define(PKT_MIN_HELLO,
    [
    'fox a 1 -1 fox hello', ?LINE_SEP,
    '{', ?LINE_SEP,
    'fox.version=s:1.0', ?LINE_SEP,
    'id=i:1', ?LINE_SEP,
    '};;', ?LINE_SEP
    ]
  ).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Parsing packet
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% expects a string
% minimal parsing
%   true -> is fox
%   false -> is not
parse_min(?CANARY ++ _Rest) ->
  true;
parse_min(_Str) ->
  false.

parse_full(?CANARY ++ Data) ->
  {true, ?CANARY ++ Data};
parse_full(?CANARY_HTTP ++ _Data) ->
  {false, http};
parse_full(?CANARY_SSH ++ _Data) ->
  {false, ssh};
parse_full(_) ->
  {false}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Forge packet
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% minimal hello
forge_min_hello() ->
  lists:concat(?PKT_MIN_HELLO).


