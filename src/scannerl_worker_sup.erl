%% OTP Supervisor for workers. Very simple in the sense that children
%% will be added dynamically.
-module(scannerl_worker_sup).
-behaviour(supervisor).
-author("Antoine Junod - antoine.junod@kudelskisecurity.com").

%% Export interface
-export([start_link/1]).

%% Export callbacks
-export([init/1]).

% called to start the supervisor
% MFA is the argument to provide to "init"
start_link(MFA = {_M,_F,_A}) ->
    %io:format("[~s] start_link called~n",[?MODULE]),
    %% might be useful for debuggin
    %process_flag(trap_exit, true),

    supervisor:start_link(
      %% For the sake of debugging and developmen simplicity, we name
      %% our supervisor with the module name (scannerl_worker_sup
      %% here).
      {local, ?MODULE},
      %% The callback module is ourself
      ?MODULE,
      %% Arguments provided to the init callback. In our case we
      %% provide the Module, Function and arguments common to all
      %% children that will take place below that supervisor.
      MFA).

% this is called by "start_link"
% MFA defines:
%   -M-odule of worker
%   -F-unction of worker to run
%   -A-rgument of worker
init({M,F,A}) ->
    %io:format("[~s] init called~n",[?MODULE]),
    SupFlags = {

      %% strategy: All child processes are dynamically added instances
      %% of the same code
      simple_one_for_one,

      %% Intensity and Period, in seconds. The selected values mean
      %% that if more than 1 restart occurs in a period of 5 seconds,
      %% all childs are killed and then the supervisor itself is
      %% killed. Processes will die if for example we cannot open a
      %% socket. think about if we need to handle that in the
      %% worker itself by catching the exit signals, because it's not
      %% an expected behavior to kill all the processes if we cannot
      %% open a new socket. If I understand correctly, we don't care
      %% about these because we plan to have children of the type
      %% 'temporary', which are not restarted in case they die.
      1, 5},

    ChildSpec = {
      %% Id: used internally to identify the ChildSepc. We use the
      %% module name of the future children
      M,

      %% Start: module, function, argument of the worker to start. In
      %% our case, is provided to init by start_link, which gets it in
      %% arguments too.
      {M, F, A},

      %% Restart: set it to temporary so that child processes will
      %% never be restarted. I guess it makes our Intensity and Period
      %% parameters caduc.
      temporary,

      %% Shutdown: set to 4 seconds. That's actually the timeout value
      %% plus one second. make
      %% that dynamic, as timeout for workers should be provided as
      %% argument.
      4,

      %% Type: we're working with workers here. So set it to
      %% worker. This is also the default value.
      worker,

      %% Modules: Using the rule of thumb from the doc. As the
      %% processes will be probably be gen_server or gen_fsm it should
      %% be a list of one element, the callback module. This is the
      %% default value.
      [M]},

    {ok,{SupFlags, [ChildSpec]}}.

