%% utils to handle and parse the options
%% provided either through the CLI or through a config file
%%
%% format of the config file is one option (see usage)
%% per line
%% empty lines and lines starting with # or % are ignored

-module(utils_opts).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-export([getopt/1, optfill/3, usage/0, get_short_hash/0, print/1]).

-include("../includes/opts.hrl").
-include("../includes/args.hrl").
-include("../includes/fpmodules.hrl").
-include("../includes/outmodules.hrl").
-include("../includes/githash.hrl").

-define(ARGSEP, ",").
-define(MODARGSEP, ":").
-define(MODARGTOK, "ma").
-define(ERL_EXT, ".erl").
-define(OUTARGSEP, ":").

-define(OPT_EQUAL, "=").
-define(OPT_DASH, "-").
-define(OPT_TRUE, "true").

% pre for modules
-define(FP_PRE, "fp_").
-define(OUT_PRE, "out_").
-define(LIST_SPACING, 18).

% default option
-define(HARDTIMEOUT, "0").
-define(DEFOUTPUT, [{out_stdout, []}]).
-define(MINRANGE, "24").
-define(DEFPROCESS, "28232").
-define(DEFPORT, "57005").
-define(INFINITY, "infinity").
-define(INFINITYATOM, infinity).

-define(ACCEPTED_ARGS, ["m", "f", "F", "d", "D", "s", "S", "o", "p", "t", "r",
  "c", "M", "P", "Q", "C", "O", "v", "l", "V", "X", "N", "x", "b", "w", "j", "h", "K"]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Usage
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% print usage
usage() ->
  print(""),
  print("USAGE"),
  print("  scannerl MODULE TARGETS [NODES] [OPTIONS]"),
  print(""),
  print("  MODULE:"),
  print("    -m <mod> --module <mod>"),
  print("      mod: the fingerprinting module to use."),
  print("           arguments are separated with a colon."),
  print(""),
  print("  TARGETS:"),
  print("    -f <target> --target <target>"),
  print("      target: a list of target separated by a comma."),
  print("    -F <path> --target-file <path>"),
  print("      path: the path of the file containing one target per line."),
  print("    -d <domain> --domain <domain>"),
  print("      domain: a list of domains separated by a comma."),
  print("    -D <path> --domain-file <path>"),
  print("      path: the path of the file containing one domain per line."),
  print(""),
  print("  NODES:"),
  print("    -s <node> --slave <node>"),
  print("      node: a list of node (hostnames not IPs) separated by a comma."),
  print("    -S <path> --slave-file <path>"),
  print("      path: the path of the file containing one node per line."),
  print("            a node can also be supplied with a multiplier (<node>*<nb>)."),
  print(""),
  print("  OPTIONS:"),
  print("    -o <mod> --output <mod>     comma separated list of output module(s) to use."),
  print("    -p <port> --port <port>     the port to fingerprint."),
  print("    -t <sec> --timeout <sec>    the fingerprinting process timeout."),
  print("    -j <nb> --max-pkt <nb>      max pkt to receive (int or \"infinity\")."),
  print("    -r <nb> --retry <nb>        retry counter (default: 0)."),
  print("    -c <cidr> --prefix <cidr>   sub-divide range with prefix > cidr (default: 24)."),
  print("    -M <port> --message <port>  port to listen for message (default: 57005)."),
  print("    -P <nb> --process <nb>      max simultaneous process per node (default: 28232)."),
  print("    -Q <nb> --queue <nb>        max nb unprocessed results in queue (default: infinity)."),
  print("    -C <path> --config <path>   read arguments from file, one per line."),
  print("    -O <mode> --outmode <mode>  0: on Master, 1: on slave, >1: on broker (default: 0)."),
  print("    -v <val> --verbose <val>    be verbose (0 <= int <= 255)."),
  print("    -K <opt> --socket <opt>     comma separated socket option (key[:value])."),
  print("    -l --list-modules           list available fp/out modules."),
  print("    -V --list-debug             list available debug options."),
  print("    -X --priv-ports             Use only source port between 1 and 1024."),
  print("    -N --nosafe                 keep going even if some slaves fail to start."),
  print("    -w --www                    DNS will try for www.<domain>."),
  print("    -b --progress               show progress."),
  print("    -x --dryrun                 dry run."),
  print(""),
  halt(1).

% return git short commit hash
get_short_hash() ->
  ?GIT_SHORT_HASH.

list_modules() ->
  % print fp modules
  print(""),
  print("Fingerprinting modules available"),
  print("================================\n"),
  print_modules(?FP_MODULES_LIST, ?FP_PRE),
  % print out modules
  print(""),
  print("Output modules available"),
  print("========================\n"),
  print_modules(?OUT_MODULES_LIST, ?OUT_PRE),
  halt(1).

list_debug() ->
  print(""),
  print("Binary combination of following values:"),
  print("  level 0   (0b 0000 0000): no debug."),
  print("  level 1   (0b 0000 0001): fpmodules debug enabled."),
  print("  level 2   (0b 0000 0010): outmodules debug enabled."),
  print("  level 4   (0b 0000 0100): broker debug enabled."),
  print("  level 8   (0b 0000 1000): master debug enabled."),
  print("  level 16  (0b 0001 0000): scannerl debug enabled."),
  print("  level 128 (0b 1000 0000): more info printed on each debug message."),
  print("  level 255 (0b 1111 1111): all debugs enabled."),
  print(""),
  halt(1).

print_modules_args([], _Cnt) ->
  ok;
print_modules_args([H|T], Cnt) ->
  Scnt = ?LIST_SPACING + 2,
  Spaces = lists:flatten([" " || _X <- lists:seq(0, Scnt)]),
  print(io_lib:fwrite("~s- Arg~p: ~s", [Spaces, Cnt, H])),
  print_modules_args(T, Cnt+1).

print_modules([], _Type) ->
  ok;
print_modules([H|Modules], Type) ->
  Name = (Type) ++ atom_to_list(H),
  %io:fwrite("~p~n", [Name]),
  %io:fwrite("~p | ~p | ~p~n", [?LIST_SPACING, length(Name), length(Type)]),
  Space = ?LIST_SPACING - length(atom_to_list(H)),
  Spaces = lists:flatten([" " || _X <- lists:seq(0, Space)]),
  print(io_lib:fwrite("~p~s~s", [H,Spaces,apply(list_to_atom(Name), get_description,[])])),
  Args = apply(list_to_atom((Type) ++ atom_to_list(H)), get_arguments, []),
  print_modules_args(Args, 1),
  print_modules(Modules, Type).

opt_print(Opt) ->
  utils:debug(scannerl, "", {}, Opt#opts.debugval),
  utils:debug(scannerl, "-------------------------------------", {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Module:      ~p", [Opt#opts.module]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Modarg:      ~p", [Opt#opts.modarg]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Target:      ~p", [Opt#opts.target]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Target-file: ~p", [Opt#opts.targetfile]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Domain:      ~p", [Opt#opts.domain]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Domain-file: ~p", [Opt#opts.domainfile]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Slave:       ~p", [Opt#opts.slave]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Slave-file:  ~p", [Opt#opts.slavefile]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Port:        ~p", [Opt#opts.port]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Timeout:     ~p", [Opt#opts.timeout]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Maxpkt:      ~p", [Opt#opts.maxpkt]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Retry:       ~p", [Opt#opts.retry]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Outmode:     ~p", [Opt#opts.outmode]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Out:         ~p", [Opt#opts.output]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Max proc:    ~p", [Opt#opts.maxchild]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Minrange:    ~p", [Opt#opts.minrange]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Dry:         ~p", [Opt#opts.dry]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Nosafe:      ~p", [Opt#opts.nosafe]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Privports:   ~p", [Opt#opts.privports]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Sockopt:     ~p", [Opt#opts.sockopt]), {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Debug:       ~p", [Opt#opts.debugval#debugval.value]),
    {}, Opt#opts.debugval),
  utils:debug(scannerl, io_lib:fwrite("Config file: ~p", [Opt#opts.config]), {}, Opt#opts.debugval),
  utils:debug(scannerl, "-------------------------------------", {}, Opt#opts.debugval),
  utils:debug(scannerl, "", {}, Opt#opts.debugval).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% options checking
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
opt_check(Opt) ->
  % test module is provided
  case Opt#opts.module of
    nil ->
      print("[ERROR] missing option -m"),
      usage();
    _ ->
      ok
  end,
  % test target is provided
  case (Opt#opts.target == [] orelse Opt#opts.target == ["true"]) andalso
    Opt#opts.targetfile == nil andalso
    (Opt#opts.domain == [] orelse Opt#opts.domain == ["true"]) andalso
    Opt#opts.domainfile == nil of
    true ->
      print("[ERROR] no target provided"),
      usage();
    false ->
      ok
  end,
  % make sure -c is a valid prefix
  case Opt#opts.minrange < 0 orelse Opt#opts.minrange > 32 of
    true ->
      print("[ERROR] bad value for -c"),
      usage();
    false ->
      ok
  end,
  % make sure -j is valid
  case Opt#opts.maxpkt == ?INFINITYATOM of
    true ->
      ok;
    false ->
      case Opt#opts.maxpkt < 1 of
        true ->
          print("[ERROR] bad value for -j"),
          usage();
        false ->
          ok
      end
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% parse Options
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
getopt(List) ->
  Opt = getopt_deep(List, maps:new()),
  List2 = read_cfg(maps:get("C", Opt, nil)),
  Opt2 = getopt_deep(List2, Opt),
  check_list_mod(maps:get("l", Opt2, nil)),
  check_list_dbg(maps:get("V", Opt2, nil)),
  check_fpmodule(maps:get("m", Opt2, nil)),
  Opt2.

% parse all arguments
getopt_deep(List, Map) ->
  New = opt_equal(List, []),
  Sep = group_opt(New, []),
  getopt(Sep, Map).

% parse a list of duplet (opt, arg)
getopt([], Acc) ->
  complete_default(Acc);
getopt([[Opt,Arg]|T], Acc) ->
  Map = add_opt(tl(Opt), Arg, Acc),
  getopt(T, Map).

% add default option if any
complete_default(Map) ->
  case maps:get("o", Map, nil) of
    nil ->
      maps:put("o", ?DEFOUTPUT, Map);
    _ ->
      Map
  end.

% group option in a list of duplets
group_opt([], Acc) ->
  Acc;
group_opt([H1|[H2|T]], Acc) ->
  case string:left(H2, 1) == ?OPT_DASH of
    true ->
      % next one is new option
      group_opt([H2|T], Acc ++ [[H1, ?OPT_TRUE]]);
    false ->
      % next one is value
      group_opt(T, Acc ++ [[H1, H2]])
  end;
group_opt([H], Acc) ->
  % handle last option
  group_opt([], Acc ++ [[H, ?OPT_TRUE]]).

% handle equals sign in arguments
opt_equal([], Acc) ->
  Acc;
opt_equal([?OPT_DASH++?OPT_DASH++_Rest=H|T], Acc) ->
  case string:str(H, ?OPT_EQUAL) of
    0 ->
      opt_equal(T, Acc ++ [H]);
    Idx ->
      {X, Y} = lists:split(Idx-1, H),
      opt_equal(T, Acc ++ [X] ++ [tl(Y)])
  end;
opt_equal([H|T], Acc) ->
  opt_equal(T, Acc ++ [H]).

% get a boolean out of string
opt_get_boolean("true") ->
  true;
opt_get_boolean("false") ->
  false;
opt_get_boolean(Val) ->
  print(io_lib:fwrite("[ERROR] bad arg: boolean format ~p", [Val])),
  usage().

% get integer out of string
opt_get_integer(nil) ->
  nil;
opt_get_integer(Val) ->
  case is_valid_integer(Val) of
    false ->
      print(io_lib:fwrite("[ERROR] bad arg: integer format ~p", [Val])),
      usage();
    true ->
      list_to_integer(Val)
  end.

get_default_args(nil) ->
  print("[ERROR] missing option -m"),
  utils_opts:usage();
get_default_args(Mod) ->
  Args = try apply(Mod, get_default_args, []) of
    Anything ->
      Anything
  catch
    _:_ ->
      print(io_lib:fwrite("[ERROR] module ~p does not exist", [Mod])),
      usage()
  end,
  Args#args{timeout=Args#args.timeout}.

optfill(Map, Mods, Version) ->
  % retrieve module default arguments
  Args = get_default_args(maps:get("m", Map, nil)),
  Opts = #opts{
    % Arguments
    module=maps:get("m", Map, nil),
    modarg=maps:get(?MODARGTOK, Map, []),
    target=maps:get("f", Map, []),
    targetfile=maps:get("F", Map, nil),
    domain=maps:get("d", Map, []),
    domainfile=maps:get("D", Map, nil),
    slave=maps:get("s", Map, []),
    slavefile=maps:get("S", Map, nil),
    port=opt_get_integer(maps:get("p", Map, integer_to_list(Args#args.port))),
    timeout=opt_get_integer(maps:get("t", Map, integer_to_list(Args#args.timeout))),
    maxpkt=maps:get("j", Map, Args#args.maxpkt),
    checkwww=opt_get_boolean(maps:get("w", Map, "false")),
    hardtimeout=opt_get_integer(maps:get("k", Map, ?HARDTIMEOUT)),
    retry=opt_get_integer(maps:get("r", Map, "0")),
    outmode=opt_get_integer(maps:get("O", Map, "0")),
    output=maps:get("o", Map, ?DEFOUTPUT),
    dry=opt_get_boolean(maps:get("x", Map, "false")),
    debugval=utils:debug_parse(maps:get("v", Map, 0)),
    minrange=opt_get_integer(maps:get("c", Map, ?MINRANGE)),
    slmodule=Mods ++ Args#args.dependencies,
    progress=opt_get_boolean(maps:get("b", Map, "false")),
    queuemax=opt_get_integer(maps:get("Q", Map, "0")),
    maxchild=opt_get_integer(maps:get("P", Map, ?DEFPROCESS)),
    nosafe=opt_get_boolean(maps:get("N", Map, "false")),
    privports=opt_get_boolean(maps:get("X", Map, "false")),
    sockopt=maps:get("K", Map, []),
    config=maps:get("k", Map, nil),
    msg_port=opt_get_integer(maps:get("M", Map, ?DEFPORT)),
    % other options
    fsmopts=Args#args.fsmopts,
    pause=false
  },
  % construct scaninfo
  Scaninfo = #scaninfo{
    version=Version,
    fpmodule=Opts#opts.module,
    port=Opts#opts.port,
    debugval=Opts#opts.debugval
  },
  opt_check(Opts),
  opt_print(Opts),
  Opts#opts{scaninfo=Scaninfo}.

parse_output_arg(Arg) ->
  Elems = string:tokens(Arg, ?OUTARGSEP),
  Mod = complete_pre(hd(Elems), ?OUT_PRE),
  {list_to_atom(Mod), tl(Elems)}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% utils
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% strip extension
strip_ext(String) ->
  case string:str(String, ?ERL_EXT) of
    0 ->
      String;
    Pos ->
      string:substr(String, 1, Pos-1)
  end.

complete_pre(String, Pre) ->
  case string:str(String, Pre) of
    0 ->
      Pre ++ String;
    1 ->
      String;
    _ ->
      Pre ++ String
  end.

% check there's a fpmodule selected
check_fpmodule(nil) ->
  utils_opts:usage();
check_fpmodule(_Mod) ->
  ok.

% check -l is selected
check_list_mod(nil) ->
  ok;
check_list_mod(_Mod) ->
  list_modules().

% check -V is selected
check_list_dbg(nil) ->
  ok;
check_list_dbg(_Mod) ->
  list_debug().

print(Msg) ->
  M = io_lib:fwrite("~s\n", [Msg]),
  io:put_chars(standard_error, M).

% well this suits our need but might not be very ethical
is_valid_integer(nil) ->
  true;
is_valid_integer(Val) ->
  Int = (catch erlang:list_to_integer(Val)),
  is_number(Int).

add_file_to_list([], Acc) ->
  Acc;
add_file_to_list([H|T], Acc) ->
  case file:read_file_info(H) of
    {ok,_} ->
      add_file_to_list(T, Acc ++ [H]);
    {error, enoent} ->
      print(io_lib:fwrite("[ERROR] Can't open target file ~p", [H])),
      usage()
  end.

% tokenizer that handles escape char
tok([$\\|Rest], Token, Acc) ->
  tok(tl(Rest), Token, [hd(Rest)|Acc]);
tok([H|T], Token, Acc) ->
  case H =:= Token of
    true ->
      [string:strip(lists:reverse(Acc))|tok(T, Token, [])];
    false ->
      tok(T, Token, [H|Acc])
  end;
tok([], _Token, Acc) ->
  [string:strip(lists:reverse(Acc))].

% accepts a single char as for example ":"
tokenize(String, Token) ->
  tok(String, hd(Token), []).

% transforms a list of element in the form "key:val"
% into a list of tuple: [{key,val},...]
keyval_to_tuple([], Agg) ->
  Agg;
keyval_to_tuple([H|T], Agg) ->
  E = string:tokens(H, ?MODARGSEP),
  Opt = case length(E) of
    1 ->
            K = list_to_atom(hd(E)),
            {K};
    2 ->
            K = list_to_atom(hd(E)),
            V = list_to_atom(hd(lists:reverse(E))),
            {K, V};
    _ ->
            {}
  end,
  keyval_to_tuple(T, Agg ++ [Opt]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% the option matching functions
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% add cli argument to maps
add_opt("o"=Key, Value, Map) ->
  Elems = tokenize(Value, ?ARGSEP),
  Tmp = lists:map(fun(X) -> parse_output_arg(X) end, Elems),
  maps:put(Key, Tmp, Map);
add_opt("m"=Key, Value, Map) ->
  Elems = tokenize(Value, ?MODARGSEP),
  % adding the module argument
  Tmp = strip_ext(hd(Elems)),
  Tmp2 = complete_pre(Tmp, ?FP_PRE),
  N = maps:put(Key, list_to_atom(Tmp2), Map),
  % arguments to the fingerprinting module are passed
  % as a list of string
  maps:put(?MODARGTOK, tl(Elems), N);
add_opt("F"=Key, Value, Map) ->
  Elems = string:tokens(Value, ?ARGSEP),
  maps:put(Key, add_file_to_list(Elems, []), Map);
add_opt("D"=Key, Value, Map) ->
  Elems = string:tokens(Value, ?ARGSEP),
  maps:put(Key, add_file_to_list(Elems, []), Map);
add_opt("t"=Key, Value, Map) ->
  maps:put(Key, integer_to_list(1000*opt_get_integer(Value)), Map);
add_opt("j"=Key, Value, Map) ->
  case string:equal(Value, ?INFINITY) of
    true ->
      maps:put(Key, ?INFINITYATOM, Map);
    false ->
      maps:put(Key, opt_get_integer(Value), Map)
  end;
add_opt("k"=Key, Value, Map) ->
  maps:put(Key, integer_to_list(1000*opt_get_integer(Value)), Map);
add_opt("K"=Key, Value, Map) ->
  Entries = string:tokens(Value, ?ARGSEP),
  maps:put(Key, keyval_to_tuple(Entries, []), Map);
add_opt("f"=Key, Value, Map) ->
  maps:put(Key, string:tokens(Value, ?ARGSEP), Map);
add_opt("d"=Key, Value, Map) ->
  maps:put(Key, string:tokens(Value, ?ARGSEP), Map);
add_opt("s"=Key, Value, Map) ->
  maps:put(Key, string:tokens(Value, ?ARGSEP), Map);
% Long options
add_opt("-module", Value, Map) ->
  add_opt("m", Value, Map);
add_opt("-target", Value, Map) ->
  add_opt("f", Value, Map);
add_opt("-target-file", Value, Map) ->
  add_opt("F", Value, Map);
add_opt("-domain", Value, Map) ->
  add_opt("d", Value, Map);
add_opt("-domain-file", Value, Map) ->
  add_opt("D", Value, Map);
add_opt("-slave", Value, Map) ->
  add_opt("s", Value, Map);
add_opt("-slave-file", Value, Map) ->
  add_opt("S", Value, Map);
add_opt("-output", Value, Map) ->
  add_opt("o", Value, Map);
add_opt("-port", Value, Map) ->
  add_opt("p", Value, Map);
add_opt("-timeout", Value, Map) ->
  add_opt("t", Value, Map);
add_opt("-ktimeout", Value, Map) ->
  add_opt("k", Value, Map);
add_opt("-prefix", Value, Map) ->
  add_opt("c", Value, Map);
add_opt("-retry", Value, Map) ->
  add_opt("r", Value, Map);
add_opt("-process", Value, Map) ->
  add_opt("P", Value, Map);
add_opt("-queue", Value, Map) ->
  add_opt("Q", Value, Map);
add_opt("-verbose", Value, Map) ->
  add_opt("v", Value, Map);
add_opt("-priv-ports", Value, Map) ->
  add_opt("X", Value, Map);
add_opt("-nosafe", Value, Map) ->
  add_opt("N", Value, Map);
add_opt("-list-modules", Value, Map) ->
  add_opt("l", Value, Map);
add_opt("-list-debug", Value, Map) ->
  add_opt("V", Value, Map);
add_opt("-dryrun", Value, Map) ->
  add_opt("x", Value, Map);
add_opt("-progress", Value, Map) ->
  add_opt("b", Value, Map);
add_opt("-www", Value, Map) ->
  maps:put("w", Value, Map);
add_opt("-direct", Value, Map) ->
  maps:put("O", Value, Map);
add_opt("-config", Value, Map) ->
  maps:put("C", Value, Map);
add_opt("-message", Value, Map) ->
  maps:put("M", Value, Map);
add_opt("-help", Value, Map) ->
  maps:put("h", Value, Map);
add_opt("-max-pkt", Value, Map) ->
  maps:put("j", Value, Map);
add_opt("-socket", Value, Map) ->
  maps:put("K", Value, Map);
add_opt(Key, Value, Map) ->
  case lists:member(Key, ?ACCEPTED_ARGS) of
    true ->
      maps:put(Key, Value, Map);
    false ->
    print("[ERROR] unknown option:"),
    print(io_lib:fwrite("\tkey: ~p", [Key])),
      print(io_lib:fwrite("\tvalue: ~p", [Value])),
      halt(1)
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Config file parser
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
read_cfg(Path) when Path == nil ->
  [];
read_cfg(Path) ->
  case utils:read_lines(Path) of
    {ok, Lines} ->
      Tmp = lists:append([string:tokens(X, " ") || X <- Lines]),
      Tmp;
    {error, Reason} ->
      print(io_lib:fwrite("[ERROR] cannot read config file: ~p", [Reason])),
      usage()
  end.

