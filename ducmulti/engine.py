"""Run a DUC engine on a fixed LOOPBACK-only backend port.

No engine's persistent exclusive profile is modified. DNS credentials are reused.
"""
from __future__ import annotations
import copy, os, pathlib, sys
from . import ENGINE_PORTS

def command(engine):
    if engine not in ENGINE_PORTS or engine=='cotten':raise ValueError('unsupported managed engine')
    from duc import core,runner
    c=copy.deepcopy(core.profiles()[engine]);port=ENGINE_PORTS[engine]
    c['udp_port']=port
    if engine=='slipstream':c['dns_listen_host']='127.0.0.1'
    if engine=='master':
        template=(core.ROOT/'engines/master/base.toml').read_text()
        rendered=runner.replace_keys(template,{
            'DOMAIN':[c['domain']],'UDP_PORT':port,'UDP_HOST':'127.0.0.1',
            'ARQ_WINDOW_SIZE':c['arq_window'],'LOG_LEVEL':c['log_level'],
            'DATA_ENCRYPTION_METHOD':c['encryption_method'],
            'ENCRYPTION_KEY_FILE':str(core.ROOT/'keys/master.key')})
        path=core.ROOT/'engines/master/multi_server_config.toml'
        runner.write_secure(path,rendered)
        binary=core.shutil.which(core.BINARIES[engine])
        if not binary:raise ValueError('Master binary absent')
        return [binary,'-config',str(path)]
    argv=runner.cmd_for(engine,c)
    if engine in ('dnstt','noizdns','vaydns'):
        flag=argv.index('-udp')
        argv[flag+1]='127.0.0.1:'+str(port)
    elif engine=='soar':
        flag=argv.index('-listen')
        argv[flag+1]='127.0.0.1:'+str(port)
    elif engine=='slipstream':
        # runner.cmd_for must honor the explicit listen host and port above.
        if '--dns-listen-host' not in argv or '--dns-listen-port' not in argv:
            raise ValueError('SlipStream CLI incompatibility')
    else:raise ValueError('Engine needs a dedicated loopback adapter')
    return argv

def main():
    if len(sys.argv)!=2:raise SystemExit('Usage: python -m ducmulti.engine ENGINE')
    from duc import core
    engine=sys.argv[1]
    conf=core.ROOT/'multi-staging.json'
    if not conf.is_file():raise SystemExit('Multi configuration is not staged')
    import json
    state=json.loads(conf.read_text())
    if engine not in state.get('engines',[]):raise SystemExit('Engine is not in approved multi configuration')
    argv=command(engine)
    os.execv(argv[0],argv)

if __name__=='__main__':main()
