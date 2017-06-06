%% a {key, value} list for the slaves
%% key: the slave
%% value: number of entries

-module(cntlist).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-export([add/3, flatten/1, merge/1, count/1, sublist/2]).
-export([flattenkeys/1, update_key/3, remove_key/2]).
-define(ELEMOFF, 1).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% interface
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% add to the list Element "Elem" with cnt "Cnt"
add(List, _Elem, Cnt) when Cnt == 0 ->
  List;
add(List, Elem, Cnt) ->
  update_cnt(List, Elem, Cnt).

% returns an erlang list with each entry being duplicated based on its count
flatten(List) ->
  flat(List, []).

% returns an erlang list with only the keys (each key once)
flattenkeys(List) ->
  flatkey(List, []).

% update the slave name (the key at ?ELEMOFF) from
% the "Current" to "New" in the list "List"
update_key(List, Current, New) ->
  case lists:keyfind(Current, ?ELEMOFF, List) of
    {Entry, Nb} ->
      lists:keydelete(Entry, ?ELEMOFF, List) ++ [{New, Nb}];
    false ->
      List
  end.

% remove a specific key
remove_key(List, Key) ->
  case lists:keyfind(Key, ?ELEMOFF, List) of
    {Entry, _Nb} ->
      lists:keydelete(Entry, ?ELEMOFF, List);
    false ->
      List
  end.

% take a list and create a cntlist
merge(List) ->
  add_from_list(List, []).

% return the total number of entries
count(List) ->
  count_elem(List, 0).

% return a sublist with cnt max elements. The elements will be proportionnally
% divided for each host. If Cnt > count(List), return List
sublist(List, Cnt) ->
  case Cnt > cntlist:count(List) of
    true ->
      List;
    false ->
      sublisthelper(List, [], Cnt, List, Cnt)
  end.

% Put most of the Elements in the list proportionnally
sublisthelper(_List, Acc, _CntTarget, _FullList, CntLeft) when CntLeft == 0 ->
  clean(Acc, []);
sublisthelper([H|T], Acc, CntTarget, FullList, CntLeft) ->
  {Elem, ElCnt} = H,
  NewElCnt = ElCnt * CntTarget div cntlist:count(FullList),
  sublisthelper(T, Acc ++ [{Elem, NewElCnt}], CntTarget, FullList, CntLeft - NewElCnt);
sublisthelper([], Acc, _CntTarget, FullList, CntLeft) ->
  sublisthelper_rest(Acc, FullList, CntLeft, Acc, FullList).

% Helper for the CntLeft.
sublisthelper_rest(_Acc1, _Acc2, CntLeft, Acc, _FullList) when CntLeft == 0 ->
  clean(Acc, []);
sublisthelper_rest([H1|T1], [H2|T2], CntLeft, Acc, FullList) ->
  {El1,El1Cnt} = H1,
  {_El2,El2Cnt} = H2,
  case  El1Cnt < El2Cnt of
    true -> % Still space for this host
      sublisthelper_rest(T1, T2, CntLeft - 1,
      cntlist:add(Acc, El1, 1), FullList);
    false -> % No space for this host, go to the next one.
      sublisthelper_rest(T1, T2, CntLeft,Acc, FullList)
  end;
sublisthelper_rest([], [], CntLeft, Acc, FullList) ->
  sublisthelper_rest(Acc, FullList, CntLeft, Acc, FullList).

% Delete nodes with 0 processes
clean([], Acc) ->
  Acc;
clean([H|T], Acc) ->
  {El, ElCnt} = H,
  clean(T, cntlist:add(Acc, El, ElCnt)).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% private
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% add entry {Elem, Cnt} if does not exist in cntlist
% or update it if exists
update_cnt(List, Elem, Cnt) ->
  case lists:keyfind(Elem, ?ELEMOFF, List) of
    {Entry, Nb} ->
      lists:keyreplace(Entry, ?ELEMOFF, List, {Entry, Nb+Cnt});
    false ->
      List ++ [{Elem, Cnt}]
  end.

% create cntlist out of List of countlist elements
add_from_list([], Agg) ->
  Agg;
add_from_list([{Elem, Cnt}|L], Agg) ->
  New = add(Agg, Elem, Cnt),
  add_from_list(L, New).

% count elements
count_elem([], Agg) ->
  Agg;
count_elem([{_, Cnt}|T], Agg) ->
  count_elem(T, Agg + Cnt).

% returns an erlang list with each entry
% being duplicated based on its count
flat([], Agg) ->
  Agg;
flat([{Elem, N}|T], Agg) ->
  flat(T, Agg ++ lists:duplicate(N, Elem)).

% returns a flatten erlang list with only
% the keys (node) without the count
flatkey([], Agg) ->
  Agg;
flatkey([{Elem, _}|T], Agg) ->
  flatkey(T, Agg ++ [Elem]).

