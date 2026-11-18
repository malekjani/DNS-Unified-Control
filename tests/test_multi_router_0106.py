import asyncio,json,pathlib,struct,tempfile,unittest
from ducmulti.router import question_name,PacketError,refuse,Resolver,Route,serve_tcp,UDPServer,load_config

def packet(name,tx=0x1234):
    q=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0\0\x10\0\x01'
    return tx.to_bytes(2,'big')+b'\x01\0\0\x01\0\0\0\0\0\0'+q

class Echo(asyncio.DatagramProtocol):
    def connection_made(self,trans):self.trans=trans
    def datagram_received(self,d,a):
        answer=d[:2]+b'\x81\x80'+d[4:]
        self.trans.sendto(answer,a)

class RouterTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.loop=asyncio.get_running_loop()
        self.backend,_=await self.loop.create_datagram_endpoint(Echo,local_addr=('127.0.0.1',0))
        self.port=self.backend.get_extra_info('sockname')[1]
        self.resolver=Resolver([Route('soar','s.test.example',self.port),Route('dnstt','d.test.example',self.port)])
    async def asyncTearDown(self):self.backend.close()
    async def test_UDP_and_transaction_id(self):
        req=packet('random.S.test.example',0x7799)
        ans=await self.resolver.query(req)
        self.assertEqual(ans[:2],b'\x77\x99');self.assertTrue(ans[2]&0x80)
    async def test_unknown_domain_refused(self):
        ans=await self.resolver.query(packet('s.test.example.evil'))
        self.assertEqual(ans[3]&15,5)
    async def test_name_parser_rejects_pointer(self):
        with self.assertRaises(PacketError):question_name(b'\x12\x34\x01\0\0\x01'+b'\0'*6+b'\xc0\x0c\0\x01\0\x01')
    async def test_no_embedded_dot_label_spoofing(self):
        # One *raw* DNS label containing a dot must never be matched as two DNS labels.
        req=(b'\x00\x01\x01\x00\x00\x01'+b'\x00'*6+
             bytes([len('a.s.test.example')])+b'a.s.test.example'+b'\x00\x00\x10\x00\x01')
        self.assertEqual((await self.resolver.query(req))[3]&15,5)
    async def test_parallel_same_ids_are_isolated(self):
        x=await asyncio.gather(*(self.resolver.query(packet('x.s.test.example',0x55aa)) for _ in range(32)))
        self.assertEqual(len(x),32)
        self.assertTrue(all(v[:2]==b'\x55\xaa' and v[2]&0x80 for v in x))
    async def test_TCP_frontend_to_udp_backend(self):
        srv=await asyncio.start_server(lambda r,w:serve_tcp(r,w,self.resolver),'127.0.0.1',0)
        port=srv.sockets[0].getsockname()[1]
        try:
            r,w=await asyncio.open_connection('127.0.0.1',port)
            for i in range(2):
                q=packet('data.d.test.example',0x1111+i)
                w.write(len(q).to_bytes(2,'big')+q);await w.drain()
                n=int.from_bytes(await r.readexactly(2),'big')
                v=await r.readexactly(n)
                self.assertEqual(v[:2],q[:2]);self.assertTrue(v[2]&0x80)
            w.close();await w.wait_closed()
        finally:srv.close();await srv.wait_closed()
    async def test_dns_UDP_frontend_to_backend(self):
        front,_=await self.loop.create_datagram_endpoint(lambda:UDPServer(self.resolver),local_addr=('127.0.0.1',0))
        import socket
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.setblocking(False)
        try:
            req=packet('x.s.test.example',0xBEEF)
            await self.loop.sock_sendto(sock,req,front.get_extra_info('sockname'))
            ans=await asyncio.wait_for(self.loop.sock_recv(sock,4096),3)
            self.assertEqual(ans[:2],req[:2]);self.assertTrue(ans[2]&0x80)
        finally:sock.close();front.close()

class StaticTests(unittest.TestCase):
    def test_overlap_rejected(self):
        with self.assertRaisesRegex(ValueError,'overlap'):
            Resolver([Route('a','a.x.example',5301),Route('b','x.example',5302)])
    def test_config_rejects_wildcard(self):
        with tempfile.TemporaryDirectory() as td:
            p=pathlib.Path(td)/'x.json';p.write_text(json.dumps({'schema':'duc.multi.router.v1','listen':'0.0.0.0','routes':[{'engine':'a','zone':'a.x.example','port':5301,'tcp':False}]}))
            with self.assertRaisesRegex(ValueError,'interface'):load_config(p)
    def test_config_accepts_aws_private(self):
        with tempfile.TemporaryDirectory() as td:
            p=pathlib.Path(td)/'x.json';p.write_text(json.dumps({'schema':'duc.multi.router.v1','listen':'172.26.2.194','routes':[{'engine':'a','zone':'a.x.example','port':5301,'tcp':False}]}))
            ip,resolver=load_config(p)
            self.assertEqual(ip,'172.26.2.194')
            self.assertEqual(resolver.route('foo.a.x.example').engine,'a')
