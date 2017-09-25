% record to store the command line arguments as well
% as other information retrieved from the modules to use
% (output, fingerprinting, ...)
-record(opts, {
    module,         % the module to use for fingerprinting
    modarg,         % module argument(s) (list of strings)
    target,         % list of target provided on CLI
    targetfile,     % file path containing target(s)
    domain,         % list of domain provided on CLI
    domainfile,     % file path containing domain(s)
    slave,          % list of slave node provided on CLI
    slavefile,      % file path containing slave node
    % -------------------------------------------------------------------
    % optional arguments
    % -------------------------------------------------------------------
    port,           % [optional] port to fingerprint
    timeout,        % [optional] fp module timeout in ms
    maxpkt,         % [optional] fp module maxpkt
    checkwww,       % [optional] dns will try to query www.target
    output,         % [optional] list of output modules to use
    retry,          % [optional] number of retry
    outmode,        % [optional] output mode (0:on master, 1:on slave, 2:on broker)
    dry,            % [optional] perform a dry run
    debugval,       % [optional] enable debug, see below
    minrange,       % [optional] sub-divide cidr bigger than this
    queuemax,       % [optional] max unprocessed results in queue
    maxchild,       % [optional] max nb of simult. process per broker
    privports,      % [optional] use privilege ports as source (between 1-1024)
    progress,       % [optional] show progress on master
    nosafe,         % [optional] keep going even if some slaves fail
    config,         % [optional] config file if any
    msg_port,       % [optional] port to listen for message (optional)
    sockopt,        % [optional] socket argument
    hardtimeout,    % [hidden] hardtimeout in ms
    % -------------------------------------------------------------------
    % fsm internals
    % -------------------------------------------------------------------
    fsmopts,        % [optional] fsm options
    % -------------------------------------------------------------------
    % internals
    % -------------------------------------------------------------------
    scaninfo,       % [internal] scaninfo for output module
    slmodule,       % [internal] modules to be sent to the slaves
    user,           % [internal] user data for master/slave comm
    pause           % [internal] pause
  }).

% record to store the scaninfo (mostly for output modules)
-record(scaninfo, {
    version,        % scannerl version
    fpmodule,       % fingerprinting module used
    port,           % target port
    debugval        % debugval
  }).

% debugging levels
% see -V
-record(debugval, {
    value,          % value
    level1,         % fpmodules
    level2,         % outmodules
    level4,         % broker
    level8,         % master
    level16,        % scannerl escript
    level32,        % N/A
    level64,        % N/A
    level128        % additional info
  }).

