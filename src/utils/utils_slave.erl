%% utils to start remote slave for scannerl
%%
%% this starts remote nodes by some kind of waiting on
%% it to respond until a specific timeout.
%% a better way of doing it (as the slave module does it)
%% would be to use a callback but for that, the module containing
%% the callback should be present on the remote host.
%% Would be doable but well ... it works
%%

-module(utils_slave).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-export([start_link/4, start_link/5, stop/2]).
-export([start_link_th/5]).

-define(BIN, "erl").
-define(REMOTE_BIN, "rsh -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no").
-define(CONNARGS, "-detached -noinput").
-define(TCPPORT, "-kernel inet_dist_listen_min").
-define(ARGS, "-hidden +K true -smp enable -P 134217727 -connect_all false -kernel dist_nodelay false").
-define(TIMEOUT, 10). % seconds
-define(POKE, 500). % poke every N ms
-define(SECTOMS, 1000).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link_th(Hostname, Name, Portmin, Dbg, Parent) ->
  {Ret, Node} = start_link(Hostname, Name, Portmin, ?TIMEOUT, Dbg),
  Parent ! {Ret, Node, Hostname, Name}.

% start a slave
% @Hostname: the hostname (must resolve)
% @Name: the name given to the node
% @Portmin: TCP port to open for the communication (through firewall)
start_link(Hostname, Name, Portmin, Dbg) ->
  start_link(Hostname, Name, Portmin, ?TIMEOUT, Dbg).

% start a slave
% @Hostname: the hostname (must resolve)
% @Name: the name given to the node
% @Timeout: how long to wait (in seconds)
% @Portmin: TCP port to open for the communication (through firewall)
start_link(Hostname, Name, Portmin, Timeout, Dbg) ->
  Node = list_to_atom(lists:concat([Name, "@", Hostname])),
  utils:debug(master, io_lib:fwrite("[uslave] connecting to \"~p\"", [Node]),
    undefined, Dbg),
  case ping_it(Node, Dbg) of
    {ok, R} ->
      {ok, R};
    error ->
      utils:debug(master, io_lib:fwrite("[uslave] starting \"~p\" on ~p", [Node, Hostname]),
        undefined, Dbg),
      start_it(Node, Hostname, Name, Portmin, Timeout*?SECTOMS, Dbg)
  end.

% stop remote node
stop(Node, Dbg) ->
  utils:debug(master, io_lib:fwrite("[uslave] halting \"~p\"", [Node]),
    undefined, Dbg),
  rpc:call(Node, erlang, halt, []),
  ok.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Utilities
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Expect Node as an atom in the form <Name>@<Hostname>
ping_it(Node, Dbg) ->
  case net_adm:ping(Node) of
    pang ->
      utils:debug(master, io_lib:fwrite("[uslave] ping ~p failed", [Node]),
        undefined, Dbg),
      error;
    pong ->
      utils:debug(master, io_lib:fwrite("[uslave] ping ~p succeed", [Node]),
        undefined, Dbg),
      {ok, Node}
  end.

% link it
setup_slave(Node) ->
  Old = process_flag(trap_exit, true),
  link(Node),
  % see http://erlang.org/doc/man/erlang.html#process_flag-2
  receive
    % discard that
    _ ->
      ok
  end,
  process_flag(trap_exit, Old).

% wait until the node is up
wait_for_node(Node, Port, Timeout, Dbg) ->
  {ok, Ref} = timer:send_after(Timeout, {slavetimeout}),
  wait_for_it(Node, Port, Ref, Dbg).

% try to ping every ?POKE until node
% is up or timeout occurs
wait_for_it(Node, Port, Ref, Dbg) ->
  receive
    {slavetimeout} ->
      utils:debug(master, "[uslave] connection timed-out after 10s",
        undefined, Dbg),
      {error, timeout}
  after
    ?POKE ->
      case ping_it(Node, Dbg) of
        {ok, N} ->
          timer:cancel(Ref),
          setup_slave(Port),
          {ok, N};
        error ->
          wait_for_it(Node, Port, Ref, Dbg)
      end
  end.

% start a remote node
start_it(Node, Hostname, Name, Portmin, Timeout, Dbg) ->
  Cmd = string:join([?REMOTE_BIN, Hostname, ?BIN, "-sname", Name,
    ?ARGS, ?TCPPORT, integer_to_list(Portmin), ?CONNARGS], " "),
  utils:debug(master, io_lib:fwrite("[uslave] remote command: ~p", [Cmd]),
    undefined, Dbg),
  Port = open_port({spawn, Cmd}, [stream]),
  wait_for_node(Node, Port, Timeout, Dbg).

