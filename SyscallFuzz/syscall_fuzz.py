
""" QNX syscall fuzzer
<alex.plaskett@mwrinfosecurity.com> - 2013
BB10 Libc exports
TODO: Remove the libc wrapper and just fuzz directly? 
Add support for COID's outside of the process
"""

from ctypes import *
from util import *

# flags for _channel_connect_attr 
#define _NTO_CHANCON_ATTR_CONFLAGS		0x00000001
#define _NTO_CHANCON_ATTR_CHANFLAGS		0x00000002
#define _NTO_CHANCON_ATTR_MODE			0x00000004
#define _NTO_CHANCON_ATTR_BUFSIZE		0x00000008
#define _NTO_CHANCON_ATTR_MAXBUF		0x00000010
#define _NTO_CHANCON_ATTR_EVENT			0x00000020
#define _NTO_CHANCON_ATTR_CURMSGS		0x00000040
#define _NTO_CHANCON_ATTR_CRED			0x00000080

class sigevent(Structure):
	_fields_ = [
	("sival_int",c_ulong),
	("sival_ptr",c_void_p)
	]

class ev(Structure):
	_fields_ = [
	("event",sigevent),
	("coid",c_ulong)
	]

class _cred_info(Structure):
	_fields_ = [
	("ruid",c_ulong),
	("euid",c_ulong),
	("suid",c_ulong),
	("rgid",c_ulong),
	("egid",c_ulong),
	("sgid",c_ulong),
	("ngroups",c_ulong),
	("grouplist",c_ulong * 8) # 8 seems to the what it is atm.
	]

class _channel_connect_attr(Union):
	_fields_ = [
	("flags",c_ulong),
	("mode_t",c_ulong),
	("bufsize",c_ulong),
	("maxbuf",c_ulong),
	("ev",ev),
	("num_curmsgs",c_ulong),
	("cred",_cred_info)
	]

# Channel flags
#define _NTO_CHF_FIXED_PRIORITY		0x0001
#define _NTO_CHF_UNBLOCK			0x0002
#define _NTO_CHF_THREAD_DEATH		0x0004
#define _NTO_CHF_DISCONNECT			0x0008
#define _NTO_CHF_NET_MSG			0x0010
#define _NTO_CHF_SENDER_LEN			0x0020
#define _NTO_CHF_COID_DISCONNECT	0x0040
#define _NTO_CHF_REPLY_LEN			0x0080
#define _NTO_CHF_STICKY				0x0100
#define _NTO_CHF_ASYNC_NONBLOCK		0x0200
#define _NTO_CHF_ASYNC				0x0400
#define _NTO_CHF_GLOBAL				0x0800

CHAN_FLAGS = [0x0001,0x0002,0x0004,0x0008,0x0010,0x0020,0x0040,0x0080,0x0100,0x0200,0x0400,0x0800]


# Conn flags
#define _NTO_COF_CLOEXEC		0x0001
#define _NTO_COF_DEAD			0x0002
#define _NTO_COF_NOSHARE		0x0040
#define _NTO_COF_NETCON			0x0080
#define _NTO_COF_NONBLOCK		0x0100
#define _NTO_COF_ASYNC			0x0200
#define _NTO_COF_GLOBAL			0x0400

CONN_FLAGS = [0x0001,0x0002,0x0040,0x0080,0x0100,0x0200,0x0400]




#typedef struct iovec
#{
#    void    *iov_base;
#    size_t   iov_len;
#} iov_t

class iovec(Structure):
	_fields_ = [
	("iov_base",c_void_p),
	("iov_len",c_ulong)
	]

class _client_info(Structure):
	_fields_ = [
	("nd",c_ulong),
	("pid",c_ulong),
	("sid",c_ulong),
	("flags",c_ulong),
	("cred",_cred_info)
	]

class _vtid_info(Structure):
	_fields = [
	("tid",c_ulong),
	("coid",c_ulong),
	("priority",c_ulong),
	("srcmsglen",c_ulong),
	("keydata",c_ulong),
	("srcnd",c_ulong),
	("dstmsglen",c_ulong),
	("zero",c_ulong)
	]


class _msg_info(Structure):
	_fields_ = [
	("nd",c_ulong),
	("srcnd",c_ulong),
	("pid",c_ulong),
	("tid",c_ulong),
	("chid",c_ulong),
	("scoid",c_ulong),
	("coid",c_ulong),
	("msglen",c_ulong),
	("srcmsglen",c_ulong),
	("dstmsglen",c_ulong),
	("priority",c_ushort),
	("flags",c_ushort),
	("reserved",c_ulong)
	]

#define _server_info	_msg_info

class _asyncmsg_connection_descriptor(Structure):
	_fields_ = [
	("flags",c_ulong),
	("sendq",c_void_p),
	("sendq_size",c_ulong),
	("sendq_head",c_ulong),
	("sendq_tail",c_ulong),
	("sendq_free",c_ulong),
	("err",c_long),
	("ev",sigevent),
	("num_curmsg",c_ulong),
	("ttimer",c_ulong),
	("block_con",c_ulong),
	("mu",c_ulong),
	("reserve",c_ulong),
	]

#struct _asyncmsg_connection_descriptor {
#	unsigned flags;							/* flags for the async connection */
#	struct _asyncmsg_put_header *sendq;		/* send queue */
#	unsigned sendq_size;				    /* send queue size */
#	unsigned sendq_head;		            /* head of the send queue */
#	unsigned sendq_tail;		            /* tail of the send queue */
#	unsigned sendq_free;		            /* start of the free list */
#	int err;								/* error status of this connection */
#	struct sigevent ev;						/* the event to be sent for notification */
#	unsigned num_curmsg;					/* number of messages pending on this connection */
#	timer_t ttimer;							/* triggering timer */
#	pthread_cond_t block_con;				/* condvar for blocking if send header queue is full */
#	pthread_mutex_t mu;						/* mutex to protect the data structure and for the condvar */
#	unsigned reserve;						/* reserve */
#	struct _asyncmsg_connection_attr attr;	/* attribute of this connection */
#	unsigned reserves[3];					/* reserve */
#};

class Syscall:

	def __init__(self):
		self.libc = CDLL("libc.so")
		self.channel_ids = []
		self.pids = [0]
		self.util = Util()

	# Not in neutrino.h
	def cache_flush(self):
		self.libc.CacheFlush()

	# Not sure args of this.
	def cache_flush_r(self):
		self.libc.CacheFlush_r()


	########################## Channel Creation Methods ##########################
	#extern int ChannelCreate(unsigned __flags);
	#extern int ChannelCreate_r(unsigned __flags);
	#extern int ChannelCreateExt(unsigned __flags, mode_t __mode, size_t __bufsize, unsigned __maxnumbuf, const struct sigevent *__ev, struct _cred_info *__cred);
	#extern int ChannelDestroy(int __chid);
	#extern int ChannelDestroy_r(int __chid);
	#extern int ConnectAttach(_Uint32t __nd, pid_t __pid, int __chid, unsigned __index, int __flags);
	#extern int ConnectAttach_r(_Uint32t __nd, pid_t __pid, int __chid, unsigned __index, int __flags);
	#extern int ConnectAttachExt(_Uint32t __nd, pid_t __pid, int __chid, unsigned __index, int __flags, struct _asyncmsg_connection_descriptor *__cd);
	#extern int ConnectDetach(int __coid);
	#extern int ConnectDetach_r(int __coid);
	#extern int ConnectServerInfo(pid_t __pid, int __coid, struct _server_info *__info);
	#extern int ConnectServerInfo_r(pid_t __pid, int __coid, struct _server_info *__info);
	#extern int ConnectClientInfo(int __scoid, struct _client_info *__info, int __ngroups);
	#extern int ConnectClientInfo_r(int __scoid, struct _client_info *__info, int __ngroups);
	#extern int ConnectFlags(pid_t __pid, int __coid, unsigned __mask, unsigned __bits);
	#extern int ConnectFlags_r(pid_t __pid, int __coid, unsigned __mask, unsigned __bits);
	#extern int ChannelConnectAttr(unsigned __id, union _channel_connect_attr *__old_attr, union _channel_connect_attr *__new_attr, unsigned __flags);
	

	def channel_create(self):
		flags = self.util.choice(CHAN_FLAGS) # Should OR flags together
		ret = self.libc.ChannelCreate(flags)
		if (ret != -1):
			print("ChannelCreate coid = ", ret)
			self.channel_ids.append(ret)
		else:
			print("ChannelCreate failed")

	# Whats the _r methods for?
	def channel_create_r(self):
		flags = self.util.choice(CHAN_FLAGS)
		ret = self.libc.ChannelCreate_r(flags)
		if (ret != -1):
			print("channel_create_r coid = ", ret)
			self.channel_ids.append(ret)
		else:
			print("ChannelCreate_r failed")

	# http://www.qnx.com/developers/docs/660/index.jsp?topic=%2Fcom.qnx.doc.neutrino.lib_ref%2Ftopic%2Fc%2Fchannelcreateext.html
	def channel_create_ext(self):
		# extern int ChannelCreateExt(unsigned __flags, mode_t __mode, size_t __bufsize, unsigned __maxnumbuf, const struct sigevent *__ev, struct _cred_info *__cred);
		flags = self.util.choice(CHAN_FLAGS)
		mode = 0 				# access permissions
		bufsize = self.util.R(0xffffffff)				
		maxnumbuf = self.util.R(0xffffffff)
		# TODO: Sort out structs
		# sigevent *
		# cred_info *
		print("Bufsize = ",bufsize)
		print("Maxnumbuf = ",maxnumbuf)
		ret = self.libc.ChannelCreateExt(flags,mode,bufsize,maxnumbuf,0,0)
		if (ret != -1):
			print("ChannelCreateExt coid = ", ret)
			self.channel_ids.append(ret)
		else:
			print("ChannelCreateExt failed")

	def channel_destory(self):
		chid = self.util.choice(self.channel_ids)
		ret = self.libc.ChannelDestroy(chid)
		if (ret != 1):
			print("ChannelDestroy worked")

	def channel_destroy_r(self):
		chid = self.util.choice(self.channel_ids)
		ret = self.libc.ChannelDestroy_r(chid)
		if (ret != 1):
			print("ChannelDestroy_r worked")

	def connect_attach(self):
		nd = 0
		pid = self.util.choice(self.pids)
		chid = self.util.choice(self.channel_ids)
		index = 0
		flags = self.util.choice(CONN_FLAGS)
		ret = self.libc.ConnectAttach(nd,pid,chid,index,flags)
		if (ret != -1):
			print("ConnectAttach = ", ret)
		else:
			print("ConnectAttach failed")

	def connect_attach_r(self):
		nd = 0
		pid = self.util.choice(self.pids)
		chid = self.util.choice(self.channel_ids)
		index = 0
		flags = self.util.choice(CONN_FLAGS)
		ret = self.libc.ConnectAttach_r(nd,pid,chid,index,flags)
		if (ret != -1):
			print("ConnectAttach = ", ret)
		else:
			print("ConnectAttach failed")

	# The struct passed to this method is really complicated and new code
	# async method handling.
	# This is undocumented
	# extern int ConnectAttachExt(_Uint32t __nd, pid_t __pid, int __chid, unsigned __index, int __flags, struct _asyncmsg_connection_descriptor *__cd);
	def connect_attach_ext(self):
		nd = 0
		pid = self.util.choice(self.pids)
		chid = self.util.choice(self.channel_ids)
		index = 0
		flags = self.util.choice(CONN_FLAGS)	
		
		# TODO: Fix the variables in this struct
		cd = _asyncmsg_connection_descriptor()

		ret = self.libc.ConnectAttach_r(nd,pid,chid,index,flags,cd)
		if (ret != -1):
			print("ConnectAttachExt = ", ret)
		else:
			print("ConnectAttachExt failed")	

	def connect_detach(self):
		coid = self.util.choice(self.channel_ids)
		ret = self.libc.ConnectDetach(coid)
		if (ret != -1):
			print("ConnectDetach failed = ", ret)
		else:
			print("ConnectDetach failed failed")	

	def connect_detach_r(self):
		coid = self.util.choice(self.channel_ids)
		self.libc.ConnectDetach_r(coid)
		if (ret != -1):
			print("ConnectDetach_r failed = ", ret)
		else:
			print("ConnectDetach_r failed failed")	


	def connect_server_info(self):
		##extern int ConnectServerInfo(pid_t __pid, int __coid, struct _server_info *__info);
		pid = 0
		coid = 0
		info = _msg_info()
		self.libc.ConnectServerInfo(pid,coid,byref(info))

	def connect_server_info_r(self):
		##extern int ConnectServerInfo(pid_t __pid, int __coid, struct _server_info *__info);
		pid = 0
		coid = 0
		info = _msg_info()
		self.libc.ConnectServerInfo_r(pid,coid,byref(info))

	# ngroups could potentially overflow here.. fixed size in the struct passed.
	def connect_client_info(self):
		#extern int ConnectClientInfo(int __scoid, struct _client_info *__info, int __ngroups);
		scoid = 0
		info = _client_info()
		ngroups = 0 
		self.libc.ConnectClientInfo(scoid,byref(info),ngroups)

	# ngroups could potentially overflow here.. fixed size in the struct passed.
	def connect_client_info_r(self):
		#extern int ConnectClientInfo(int __scoid, struct _client_info *__info, int __ngroups);
		scoid = 0
		info = _client_info()
		ngroups = 0 
		self.libc.ConnectClientInfo_r(scoid,byref(info),ngroups)

	def connect_flags(self):
		#extern int ConnectFlags(pid_t __pid, int __coid, unsigned __mask, unsigned __bits);
		pid = 0
		coid = 0
		mask = 0
		bits = 0
		self.libc.ConnectFlags(pid,coid,mask,bits)

	def connect_flags_r(self):
		#extern int ConnectFlags(pid_t __pid, int __coid, unsigned __mask, unsigned __bits);
		pid = 0
		coid = 0
		mask = 0
		bits = 0
		self.libc.ConnectFlags_r(pid,coid,mask,bits)

	# This is interesting, conn_attr is complicated struct.
	def channel_conn_attr(self):
		# #extern int ChannelConnectAttr(unsigned __id, union _channel_connect_attr *__old_attr, union _channel_connect_attr *__new_attr, unsigned __flags);
		__id = 0
		__old_attr = _channel_connect_attr()
		__new_attr = _channel_connect_attr()
		flags = 0
		self.libc.ChannelConnectAttr(__id,__old_attr,__new_attr,flags)


	################################ Messaging Methods ###############################

	def msg_send(self):
		# extern int MsgSend(int __coid, const void *__smsg, int __sbytes, void *__rmsg, int __rbytes);
		send_buf = create_string_buffer(10)
		recv_buf = create_string_buffer(10)
		coid = 0 # Id if channel from ConnectAttach
		__smsg = send_buf
		sbytes = 0
		__rmsg = recv_buf
		rbytes = 0
		self.libc.MsgSend(coid,__smsg,len(__smsg),__rmsg,len(__rmsg))

	def msg_send_r(self):
		# extern int MsgSend(int __coid, const void *__smsg, int __sbytes, void *__rmsg, int __rbytes);
		send_buf = create_string_buffer(10)
		recv_buf = create_string_buffer(10)
		coid = 0 # Id if channel from ConnectAttach
		__smsg = send_buf
		sbytes = 0
		__rmsg = recv_buf
		rbytes = 0
		self.libc.MsgSend_r(coid,__smsg,len(__smsg),__rmsg,len(__rmsg))	

	# extern int MsgSendnc(int __coid, const void *__smsg, int __sbytes, void *__rmsg, int __rbytes);
	# nc is non-cancelation point
	def msg_send_nc(self):
		send_buf = create_string_buffer(10)
		recv_buf = create_string_buffer(10)
		coid = 0 # Id if channel from ConnectAttach
		__smsg = send_buf
		sbytes = 0
		__rmsg = recv_buf
		rbytes = 0
		self.libc.MsgSendnc(coid,__smsg,len(__smsg),__rmsg,len(__rmsg))	

	def msg_send_nc_r(self):
		send_buf = create_string_buffer(10)
		recv_buf = create_string_buffer(10)
		coid = 0 # Id if channel from ConnectAttach
		__smsg = send_buf
		sbytes = 0
		__rmsg = recv_buf
		rbytes = 0
		self.libc.MsgSendnc_r(coid,__smsg,len(__smsg),__rmsg,len(__rmsg))	

	#extern int MsgSendsv(int __coid, const void *__smsg, int __sbytes, const struct iovec *__riov, int __rparts);
	def msg_send_sv(self):
		coid = 0
		send_buf = create_string_buffer(10)
		sbytes = len(send_buf)
		iov = iovec()
		rparts = 0
		self.libc.MsgSendsv(coid,send_buf,sbytes,byref(iov),rparts)


	def msg_send_sv_r(self):
		coid = 0
		send_buf = create_string_buffer(10)
		sbytes = len(send_buf)
		iov = iovec()
		rparts = 0
		self.libc.MsgSendsv_r(coid,send_buf,sbytes,byref(iov),rparts)

	# extern int MsgSendsvnc(int __coid, const void *__smsg, int __sbytes, const struct iovec *__riov, int __rparts);
	def msg_send_svnc(self):
		coid = 0
		send_buf = create_string_buffer(10)
		sbytes = len(send_buf)
		iov = iovec()
		rparts = 0
		self.libc.MsgSendsvnc(coid,send_buf,sbytes,byref(iov),rparts)

	def msg_send_svnc_r(self):
		coid = 0
		send_buf = create_string_buffer(10)
		sbytes = len(send_buf)
		iov = iovec()
		rparts = 0
		self.libc.MsgSendsvnc_r(coid,send_buf,sbytes,byref(iov),rparts)		

	#extern int MsgSendvs(int __coid, const struct iovec *__siov, int __sparts, void *__rmsg, int __rbytes);
	def msg_send_vs(self):
		coid = 0
		siov = iovec()
		sparts = 0
		rmsg = create_string_buffer(10)
		rbytes = 0
		self.libc.MsgSendsvnc_r(coid,byref(siov),sparts,rmsg,rbytes)	

	def msg_send_vs_r(self):
		coid = 0
		siov = iovec()
		sparts = 0
		rmsg = create_string_buffer(10)
		rbytes = 0
		self.libc.MsgSendsvnc_r(coid,byref(siov),sparts,rmsg,rbytes)

	#extern int MsgSendvsnc(int __coid, const struct iovec *__siov, int __sparts, void *__rmsg, int __rbytes);
	def msg_send_vsnc(self):
		coid = 0
		siov = iovec()
		sparts = 0
		rmsg = create_string_buffer(10)
		rbytes = 0
		self.libc.MsgSendvsnc(coid,byref(siov),sparts,rmsg,rbytes)
	#extern int MsgSendvsnc_r(int __coid, const struct iovec *__siov, int __sparts, void *__rmsg, int __rbytes);
	def msg_send_vsnc_r(self):
		coid = 0
		siov = iovec()
		sparts = 0
		rmsg = create_string_buffer(10)
		rbytes = 0
		self.libc.MsgSendvsnc_r(coid,byref(siov),sparts,rmsg,rbytes)

	# extern int MsgSendv(int __coid, const struct iovec *__siov, int __sparts, const struct iovec *__riov, int __rparts);
	# extern int MsgSendv_r(int __coid, const struct iovec *__siov, int __sparts, const struct iovec *__riov, int __rparts);
	def msg_send_v(self):
		coid = 0
		siov = iovec()
		sparts = 0
		riov = iovec()
		rparts = 0
		self.libc.MsgSendv(coid,byref(siov),sparts,byref(riov),rparts)

	def msg_send_v_r(self):
		coid = 0
		siov = iovec()
		sparts = 0
		riov = iovec()
		rparts = 0
		self.libc.MsgSendv_r(coid,byref(siov),sparts,byref(riov),rparts)

	def msg_send_vnc(self):
		coid = 0
		siov = iovec()
		sparts = 0
		riov = iovec()
		rparts = 0
		self.libc.MsgSendvnc(coid,byref(siov),sparts,byref(riov),rparts)

	def msg_send_vnc_r(self):
		coid = 0
		siov = iovec()
		sparts = 0
		riov = iovec()
		rparts = 0
		self.libc.MsgSendvnc_r(coid,byref(siov),sparts,byref(riov),rparts)

	#extern int MsgReceive(int __chid, void *__msg, int __bytes, struct _msg_info *__info);
	#extern int MsgReceive_r(int __chid, void *__msg, int __bytes, struct _msg_info *__info);
	def msg_receive(self):
		chid = 0
		__msg = create_string_buffer(10)
		bytes = 0
		__info = _msg_info()
		self.libc.MsgReceive(chid,__msg,bytes,byref(__info))

	def msg_receive_r(self):
		chid = 0
		__msg = create_string_buffer(10)
		bytes = 0
		__info = _msg_info()
		self.libc.MsgReceive_r(chid,__msg,bytes,byref(__info))		

	#extern int MsgReceivev(int __chid, const struct iovec *__iov, int __parts, struct _msg_info *__info);
	#extern int MsgReceivev_r(int __chid, const struct iovec *__iov, int __parts, struct _msg_info *__info);
	def msg_receive_v(self):
		chid = 0
		iov = iovec()
		__parts = 0
		__info = _msg_info()
		self.libc.MsgReceivev(chid,iov,__parts,__info)

	def msg_receive_v_r(self):
		chid = 0
		iov = iovec()
		__parts = 0
		__info = _msg_info()
		self.libc.MsgReceivev_r(chid,iov,__parts,__info)

	#extern int MsgReceivePulse(int __chid, void *__pulse, int __bytes, struct _msg_info *__info);
	#extern int MsgReceivePulse_r(int __chid, void *__pulse, int __bytes, struct _msg_info *__info);
	def msg_receive_pulse(self):
		chid = 0
		buf = create_string_buffer(256)
		__bytes = 0
		__info = None
		self.libc.MsgReceivePulse(chid,buf,__bytes,__info)

	def msg_receive_pulse_r(self):
		chid = 0
		buf = create_string_buffer(256)
		__bytes = 0
		__info = None
		self.libc.MsgReceivePulse_r(chid,buf,__bytes,__info)

	#extern int MsgReceivePulsev(int __chid, const struct iovec *__iov, int __parts, struct _msg_info *__info);
	#extern int MsgReceivePulsev_r(int __chid, const struct iovec *__iov, int __parts, struct _msg_info *__info);
	# todo

	#extern int MsgReply(int __rcvid, int __status, const void *__msg, int __bytes);
	#extern int MsgReply_r(int __rcvid, int __status, const void *__msg, int __bytes);

	def msg_reply(self):
		rcvid = 0
		__status = 0
		__msg = create_string_buffer(256)
		bytes = 0
		self.libc.MsgReply(rcvid,__status,__msg,bytes)

	def msg_reply_r(self):
		rcvid = 0
		__status = 0
		__msg = create_string_buffer(256)
		bytes = 0
		self.libc.MsgReply_r(rcvid,__status,__msg,bytes)

	#extern int MsgReplyv(int __rcvid, int __status, const struct iovec *__iov, int __parts);
	#extern int MsgReplyv_r(int __rcvid, int __status, const struct iovec *__iov, int __parts);
	def msg_reply_v(self):
		rcvid = 0
		__status = 0
		iov = iovec()
		__parts = 0
		self.libc.MsgReplyv(rcvid,__status,byref(iov),__parts)

	def msg_reply_v_r(self):
		rcvid = 0
		__status = 0
		iov = iovec()
		__parts = 0
		self.libc.MsgReplyv_r(rcvid,__status,byref(iov),__parts)

	#extern int MsgReadiov(int __rcvid, const struct iovec *__iov, int __parts, int __offset, int __flags);
	#extern int MsgReadiov_r(int __rcvid, const struct iovec *__iov, int __parts, int __offset, int __flags);
	def msg_read_iov(self):
		rcvid = 0
		iov = iovec()
		__parts = 0
		__offset = 0
		__flags = 0
		self.libc.MsgReadiov(rcvid,byref(iov),__parts,__offset,__flags)


	def msg_read_iov_r(self):
		rcvid = 0
		iov = iovec()
		__parts = 0
		__offset = 0
		__flags = 0
		self.libc.MsgReadiov_r(rcvid,byref(iov),__parts,__offset,__flags)

	#extern int MsgRead(int __rcvid, void *__msg, int __bytes, int __offset);
	#extern int MsgRead_r(int __rcvid, void *__msg, int __bytes, int __offset);
	def msg_read(self):
		rcvid = 0
		__msg = create_string_buffer(256)
		__bytes = 0
		__offset = 0
		self.libc.MsgRead(rcvid,__msg,__bytes,__offset)

	def msg_read_r(self):
		rcvid = 0
		__msg = create_string_buffer(256)
		__bytes = 0
		__offset = 0
		self.libc.MsgRead_r(rcvid,__msg,__bytes,__offset)

	#extern int MsgReadv(int __rcvid, const struct iovec *__iov, int __parts, int __offset);
	#extern int MsgReadv_r(int __rcvid, const struct iovec *__iov, int __parts, int __offset);
	def msg_readv(self):
		__rcvid = 0
		iov = iovec()
		__parts = 0
		__offset = 0
		self.libc.MsgReadv(__rcvid,byref(iov),__parts,__offset)

	def msg_readv_r(self):
		__rcvid = 0
		iov = iovec()
		__parts = 0
		__offset = 0
		self.libc.MsgReadv_r(__rcvid,byref(iov),__parts,__offset)

	#extern int MsgWrite(int __rcvid, const void *__msg, int __bytes, int __offset);
	#extern int MsgWrite_r(int __rcvid, const void *__msg, int __bytes, int __offset);
	def msg_write(self):
		__rcvid = 0
		__msg = create_string_buffer(256)
		__bytes = len(__msg)
		__offset = 0
		self.libc.MsgWrite(__rcvid,__msg,__bytes,__offset)

	def msg_write_r(self):
		__rcvid = 0
		__msg = create_string_buffer(256)
		__bytes = len(__msg)
		__offset = 0
		self.libc.MsgWrite_r(__rcvid,__msg,__bytes,__offset)

	#extern int MsgWritev(int __rcvid, const struct iovec *__iov, int __parts, int __offset);
	#extern int MsgWritev_r(int __rcvid, const struct iovec *__iov, int __parts, int __offset);
	def msg_write_v(self):
		__rcvid = 0
		iov = iovec()
		__parts = 0
		__offset = 0
		self.libc.MsgWritev(__rcvid,byref(iov),__parts,__offset)

	def msg_write_v_r(self):
		__rcvid = 0
		iov = iovec()
		__parts = 0
		__offset = 0
		self.libc.MsgWritev_r(__rcvid,byref(iov),__parts,__offset)

	#extern int MsgSendPulse(int __coid, int __priority, int __code, int __value);
	#extern int MsgSendPulse_r(int __coid, int __priority, int __code, int __value);
	def msg_send_pulse(self):
		__coid = 0
		__priority = 0
		__code = 0 # TODO: find out pulse codes
		__value = 0
		self.libc.MsgSendPulse(__coid,__priority,__code,__value)

	def msg_send_pulse_r(self):
		__coid = 0
		__priority = 0
		__code = 0 # TODO: find out pulse codes
		__value = 0
		self.libc.MsgSendPulse(__coid,__priority,__code,__value)

	# extern int MsgDeliverEvent(int __rcvid, const struct sigevent *__event);
	# extern int MsgDeliverEvent_r(int __rcvid, const struct sigevent *__event);	
	def msg_deliver_event(self):
		__rcvid = 0
		__event = sigevent()
		self.libc.MsgDeliverEvent(__rcvid,byref(__event))

	def msg_deliver_event_r(self):
		__rcvid = 0
		__event = sigevent()
		self.libc.MsgDeliverEvent_r(__rcvid,byref(__event))

	# extern int MsgVerifyEvent(int __rcvid, const struct sigevent *__event);
	# extern int MsgVerifyEvent_r(int __rcvid, const struct sigevent *__event);
	def msg_verify_event(self):
		__rcvid = 0
		__event = sigevent()
		self.libc.MsgVerifyEvent(__rcvid,byref(__event))

	def msg_verify_event_r(self):
		__rcvid = 0
		__event = sigevent()
		self.libc.MsgVerifyEvent_r(__rcvid,byref(__event))

	#extern int MsgInfo(int __rcvid, struct _msg_info *__info);
	#extern int MsgInfo_r(int __rcvid, struct _msg_info *__info);
	def msg_info(self):
		__rcvid = 0
		__info = _msg_info()
		self.libc.MsgInfo(__rcvid,byref(__info))

	def msg_info_r(self):
		__rcvid = 0
		__info = _msg_info()
		self.libc.MsgInfo_r(__rcvid,byref(__info))

	#extern int MsgKeyData(int __rcvid, int __oper, _Uint32t __key, _Uint32t *__newkey, const struct iovec *__iov, int __parts);
	#extern int MsgKeyData_r(int __rcvid, int __oper, _Uint32t __key, _Uint32t *__newkey, const struct iovec *__iov, int __parts);
	def msg_key_data(self):
		__rcvid = 0
		__oper = 0
		__key = 0
		__newkey = 0
		__iov = iovec()
		__parts = 0
		self.libc.MsgKeyData(__rcvid,__oper,__key,__newkey,__iov,__parts)

	def msg_key_data_r(self):
		__rcvid = 0
		__oper = 0
		__key = 0
		__newkey = 0
		__iov = iovec()
		__parts = 0
		self.libc.MsgKeyData_r(__rcvid,__oper,__key,__newkey,__iov,__parts)

	#extern int MsgError(int __rcvid, int __err);
	#extern int MsgError_r(int __rcvid, int __err);
	def msg_error(self):
		__rcvid = 0
		__err = 0
		self.libc.MsgError(__rcvid,__err)

	def msg_error_r(self):
		__rcvid = 0
		__err = 0
		self.libc.MsgError_r(__rcvid,__err)	

	#extern int MsgCurrent(int __rcvid);
	#extern int MsgCurrent_r(int __rcvid);
	def msg_current(self):
		__rcvid = 0
		self.libc.MsgCurrent(__rcvid)

	def msg_current_r(self):
		__rcvid = 0
		self.libc.MsgCurrent_r(__rcvid)

	# extern int MsgSendAsyncGbl(int __coid, const void *__smsg, size_t __sbytes, unsigned __msg_prio);
	def msg_send_async_gbl(self):
		__coid = 0
		__smsg = create_string_buffer(256)
		sbytes = len(__smsg)
		__msg_prio = 0
		self.libc.MsgSendAsyncGbl(__coid,__smsg,sbytes,__msg_prio)

	# extern int MsgSendAsync(int __coid);
	def msg_send_async(self):
		__coid = 0
		self.libc.MsgSendAsync(__coid)

	# extern int MsgReceiveAsyncGbl(int __chid, void *__rmsg, size_t __rbytes, struct _msg_info *__info, int __coid);
	def msg_receive_async_gbl(self):
		__chid = 0
		__rmsg = create_string_buffer(256)
		__rbytes = len(__rmsg)
		__info = _msg_info()
		__coid = 0
		self.libc.MsgReceiveAsyncGbl(__chid,__rmsg,__rbytes,__info,__coid)

	# extern int MsgReceiveAsync(int __chid, const struct iovec *__iov, unsigned __parts);
	def msg_receive_async(self):
		__chid = 0
		iov = iovec()
		__parts = 0
		self.libc.MsgReceiveAsync(__chid,byref(iov),__parts)

	# Signal stuff next

	############################ Clock Methods ##################################
	# TODO
	def clock_adjust(self):
		# ClockAdjust(clockid_t __id, const struct _clockadjust *_new, struct _clockadjust *__old);
		__id = c_ulong()

	# QNET kernel stuff #########################################################
	def net_cred(self):
		#extern int NetCred(int __coid, const struct _client_info *__info);
		coid = 0
		ci = _client_info()

	def net_vtid(self):
		__vtid = 0
		__info = _vtid_info()
		#extern int NetVtid(int __vtid, const struct _vtid_info *__info);

	def net_unblock(self):
		# extern int NetUnblock(int __vtid);
		vtid = 0

	def net_info_scoid(self):
		# __remote_scoid - Can't find this defined anywhere.
		# extern int NetInfoscoid(int __local_scoid, int __remote_scoid);
		pass

	

if __name__ == "__main__":
	syscall = Syscall()
	syscall.channel_create()
	syscall.channel_create_r()
	syscall.channel_create_ext()
	syscall.channel_destory()
	syscall.connect_attach()
	syscall.connect_attach_ext()