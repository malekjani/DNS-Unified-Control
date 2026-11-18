"""Small, fail-closed DNS question router for DUC's dedicated zones.

Only the first DNS question is inspected. Payloads are forwarded unchanged.
Each upstream request uses an isolated UDP socket, avoiding cross-client ID
collisions without modifying opaque DNS tunnel data. This is deliberately a
bounded correctness-first router, not yet a high-throughput dataplane.
"""
from __future__ import annotations
import argparse, asyncio, ipaddress, json, pathlib, socket, struct
from dataclasses import dataclass

MAX_PACKET=4096
MAX_PENDING=256

class PacketError(ValueError): pass

def question_name(packet: bytes) -> str:
    if len(packet)<17: raise PacketError('short DNS query')
    flags=int.from_bytes(packet[2:4],'big')
    if flags & 0x8000: raise PacketError('not a query')
    if ((flags>>11)&15)!=0 or (flags&0x0200): raise PacketError('unsupported query flags')
    if int.from_bytes(packet[4:6],'big')!=1: raise PacketError('one question required')
    pos=12; labels=[]
    while True:
        if pos>=len(packet): raise PacketError('truncated name')
        size=packet[pos];pos+=1
        if size==0:break
        if size & 0xc0 or size>63: raise PacketError('compressed or invalid qname')
        if pos+size>len(packet):raise PacketError('truncated label')
        label=packet[pos:pos+size]
        if any(ch<33 or ch>126 or ch==46 for ch in label):raise PacketError('invalid label')
        labels.append(label.decode('ascii').lower());pos+=size
        if len(labels)>127 or pos>253+12:raise PacketError('name too long')
    if not labels or pos+4>len(packet):raise PacketError('missing question type/class')
    if int.from_bytes(packet[pos+2:pos+4],'big')!=1:raise PacketError('non-IN query')
    return '.'.join(labels)

def refuse(packet:bytes)->bytes:
    if len(packet)<12:return b''
    # QR=1, RA=0, RCODE=5; preserve RD only. Never claim recursion.
    flags=0x8005 | (int.from_bytes(packet[2:4],'big')&0x0100)
    # No question in the response for untrusted or malformed packets.
    return packet[:2]+flags.to_bytes(2,'big')+b'\x00'*8

@dataclass(frozen=True)
class Route:
    engine:str
    zone:str
    port:int
    tcp:bool=False

class Resolver:
    def __init__(self, routes):
        self.routes=tuple(routes)
        zones=[r.zone for r in self.routes]
        if len(set(zones))!=len(zones):raise ValueError('duplicate zone')
        for a in zones:
            for b in zones:
                if a!=b and a.endswith('.'+b):raise ValueError('overlapping zones')
        self.limit=asyncio.Semaphore(MAX_PENDING)
    def route(self, name):
        for r in self.routes:
            if name==r.zone or name.endswith('.'+r.zone):return r
        return None
    async def query(self, packet:bytes, tcp_client:bool=False)->bytes:
        try:
            name=question_name(packet)
        except PacketError:
            return refuse(packet)
        r=self.route(name)
        if r is None:return refuse(packet)
        async with self.limit:
            try:
                if tcp_client and r.tcp:return await self._tcp(r.port,packet)
                return await self._udp(r.port,packet)
            except (TimeoutError,OSError,ValueError,asyncio.IncompleteReadError):
                return b''  # Fail closed; client may retry, never route to wrong engine.
    @staticmethod
    async def _udp(port:int,packet:bytes)->bytes:
        loop=asyncio.get_running_loop()
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_sendto(sock,packet,('127.0.0.1',port))
            result,_=await asyncio.wait_for(loop.sock_recvfrom(sock,MAX_PACKET),timeout=2)
            if len(result)<12 or result[:2]!=packet[:2] or not (result[2]&0x80):
                raise ValueError('invalid backend transaction')
            return result
        finally:sock.close()
    @staticmethod
    async def _tcp(port:int,packet:bytes)->bytes:
        reader,writer=await asyncio.wait_for(asyncio.open_connection('127.0.0.1',port),2)
        try:
            writer.write(len(packet).to_bytes(2,'big')+packet)
            await asyncio.wait_for(writer.drain(),2)
            size=int.from_bytes(await asyncio.wait_for(reader.readexactly(2),2),'big')
            if size<12 or size>MAX_PACKET:raise ValueError('bad TCP response length')
            result=await asyncio.wait_for(reader.readexactly(size),2)
            if result[:2]!=packet[:2] or not(result[2]&0x80):raise ValueError('invalid backend response')
            return result
        finally:
            writer.close()
            await writer.wait_closed()

class UDPServer(asyncio.DatagramProtocol):
    def __init__(self,resolver):self.resolver=resolver;self.transport=None;self.tasks=set()
    def connection_made(self,transport):self.transport=transport
    def datagram_received(self,data,addr):
        if len(data)>MAX_PACKET:return
        if len(self.tasks)>=MAX_PENDING*2:return
        task=asyncio.create_task(self.answer(data,addr))
        self.tasks.add(task);task.add_done_callback(self.tasks.discard)
    async def answer(self,data,addr):
        answer=await self.resolver.query(data)
        if answer and self.transport:self.transport.sendto(answer,addr)

async def serve_tcp(reader,writer,resolver):
    try:
        for _ in range(128):
            header=await asyncio.wait_for(reader.readexactly(2),timeout=15)
            size=int.from_bytes(header,'big')
            if size<12 or size>MAX_PACKET:break
            data=await asyncio.wait_for(reader.readexactly(size),timeout=15)
            answer=await resolver.query(data,tcp_client=True)
            if not answer:break
            writer.write(len(answer).to_bytes(2,'big')+answer)
            await asyncio.wait_for(writer.drain(),5)
    except (asyncio.TimeoutError,asyncio.IncompleteReadError,ConnectionError,OSError):pass
    finally:
        writer.close()
        try:await writer.wait_closed()
        except (ConnectionError,OSError):pass

def load_config(path):
    data=json.loads(pathlib.Path(path).read_text())
    if set(data)!={'schema','listen','routes'} or data['schema']!='duc.multi.router.v1':raise ValueError('unknown config')
    ip=str(ipaddress.IPv4Address(data['listen']))
    if ip=='0.0.0.0' or ip.startswith('127.') or ip.startswith('224.'):
        raise ValueError('router must bind an explicitly selected non-loopback interface IP')
    routes=[]
    for r in data['routes']:
        if set(r)!={'engine','zone','port','tcp'}:raise ValueError('unexpected route fields')
        z=str(r['zone']).strip().lower().rstrip('.')
        if len(z)>253 or not z or not all(x and len(x)<64 and x.isascii() and x.replace('-','').isalnum() for x in z.split('.')):raise ValueError('bad zone')
        p=r['port']
        if type(p)!=int or not 1024<=p<=65535:raise ValueError('bad port')
        if type(r['tcp']) is not bool:raise ValueError('bad tcp')
        routes.append(Route(str(r['engine']),z,p,r['tcp']))
    if not routes:raise ValueError('empty router configuration')
    return ip,Resolver(routes)

async def main_async(path):
    listen,resolver=load_config(path)
    loop=asyncio.get_running_loop()
    udp,_=await loop.create_datagram_endpoint(lambda:UDPServer(resolver),local_addr=(listen,53))
    try:
        tcp=await asyncio.start_server(lambda r,w:serve_tcp(r,w,resolver),listen,53,backlog=128)
        async with tcp:await tcp.serve_forever()
    finally:udp.close()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',required=True)
    a=parser.parse_args()
    asyncio.run(main_async(a.config))

if __name__=='__main__':main()
