% record to store the arguments that are given
% to the fingerprinting module for each of the provided
% targets. It also contains internal args used by the FSM.
-record(args, {
    id,              % the id of this process
    parent,          % parent pid
    % ----------------------------------------------------------------------
    % cli arguments
    % ----------------------------------------------------------------------
    module,          % the module to use for fingerprinting
    target,          % [original] the target to fingerprint
    port,            % [original] port to fingerprint
    retry=0,         % [optional] number of retry when timed out
    checkwww,        % [optional] dns will check for www.target
    arguments=[],    % [optional] module arguments (list of strings)
    debugval,        % [optional] debugging value
    privports,       % [optional] use privilege ports only
    sockopt,         % [optional] socket argument
    % ----------------------------------------------------------------------
    % module arguments
    % ----------------------------------------------------------------------
    type,            % fsm type (tcp, udp, ssl, ...)
    timeout=3000,    % [optional] fp module timeout in ms
    maxpkt=infinity, % [optional] max packet to receive
    dependencies=[], % [optional] of modules needed by the module to work
    % ----------------------------------------------------------------------
    % fsm arguments
    % ----------------------------------------------------------------------
    fsmopts=[],      % [optional] fsm options
    % ----------------------------------------------------------------------
    % output specific
    % when direct == true, outobj contains the output objects
    % when direct == false, parent is where result should be sent
    % ----------------------------------------------------------------------
    outobj,          % output objects
    direct=false,    % direct output results (do not send to parent)
    % ----------------------------------------------------------------------
    % FSM internals
    % ----------------------------------------------------------------------
    ctarget,         % effective target to connect to
    cport,           % effective port to connect to
    ipaddr,          % the ip of the target to fingerprint
    eaccess_retry=0, % retry cnt when receiving a eaccess with privports
    eaccess_max=2,   % max retry when eacces occurs
    retrycnt,        % retry counter
    packetrcv = 0,   % amount of packet received
    sending = false, % helper for fsm
    datarcv = << >>, % the data packet received
    payload = << >>, % the payload to send
    socket,          % socket used to connect
    nbpacket,        % amount of packets to wait for
    result={{error,unknown},fsm_issue},          % the result data
    sndreason,       % the reason when sending
    rcvreason,       % the reason when receiving
    % ----------------------------------------------------------------------
    % runtime reserved space
    % ----------------------------------------------------------------------
    moddata          % fp_module internal data
  }).
