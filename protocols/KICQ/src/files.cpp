/*
Copyright (C) 2026 Miranda NG team

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation version 2
of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

// File transfer: an offer travels as a channel 2 ICBM (the rendezvous), the file itself over
// a separate TCP connection. The sender takes a slot on an ARS proxy and names it in the offer,
// the receiver joins that slot, the proxy pairs both by the cookie and sends READY to each.
// From then on the proxy is a transparent pipe carrying OFT2: a 256 byte prompt from the
// sender, an ack from the receiver, the raw bytes of the file, a "done" from the receiver.

#include "stdafx.h"

#define PROXY_VERSION 0x044A

enum { PROXY_ERROR = 1, PROXY_ALLOCATE = 2, PROXY_ALLOCATE_OK = 3, PROXY_JOIN = 4, PROXY_READY = 5 };
enum { OFT_PROMPT = 0x0101, OFT_ACK = 0x0202, OFT_DONE = 0x0204 };

// offsets inside an OFT2 header
enum { OFT_TYPE = 6, OFT_COOKIE = 8, OFT_FILES_LEFT = 0x16, OFT_SIZE = 0x20, OFT_RECEIVED = 0x3C, OFT_RECV_SUM = 0x40, OFT_ENCODING = 0xBC, OFT_NAME = 0xC0 };

#define FT_TIMEOUT       60    // silence on a transfer connection, seconds
#define FT_JOIN_TIMEOUT  120   // the proxy keeps an unanswered slot for that long
#define FT_CHUNK         16384

static uint32_t oftChecksum(const uint8_t *data, size_t len, uint32_t prev, bool bOdd)
{
	uint32_t sum = (prev >> 16) & 0xFFFF;
	for (size_t i = 0; i < len; i++) {
		uint32_t old = sum;
		sum -= ((i & 1) != (size_t)bOdd) ? data[i] : uint32_t(data[i]) << 8;
		if (sum > old)
			sum--;
	}
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	return sum << 16;
}

static uint32_t readBE32(const bytes_t &d, int off)
{
	return OscarReader(d, off).u32();
}

static void writeBE32(bytes_t &d, int off, uint32_t v)
{
	for (int i = 0; i < 4; i++)
		d[off + i] = char(v >> (8 * (3 - i)));
}

// a name that came from the network must not leave the folder the user has chosen
static CMStringW sanitizeFileName(const CMStringW &wszName)
{
	CMStringW res(wszName);
	int idx = max(res.ReverseFind('\\'), res.ReverseFind('/'));
	if (idx != -1)
		res.Delete(0, idx + 1);

	for (int i = 0; i < res.GetLength(); i++)
		if (res[i] < 32 || wcschr(L"<>:\"|?*", res[i]))
			res.SetAt(i, '_');

	res.TrimRight(L". ");
	res.TrimLeft();
	if (res.IsEmpty())
		return L"file";

	CMStringW wszBase(res);
	idx = wszBase.Find('.');
	if (idx != -1)
		wszBase.Truncate(idx);
	static const wchar_t *reserved[] = { L"CON", L"PRN", L"AUX", L"NUL", L"COM1", L"COM2", L"COM3", L"COM4", L"COM5", L"COM6",
		L"COM7", L"COM8", L"COM9", L"LPT1", L"LPT2", L"LPT3", L"LPT4", L"LPT5", L"LPT6", L"LPT7", L"LPT8", L"LPT9" };
	for (auto *it : reserved)
		if (!wszBase.CompareNoCase(it))
			return L"_" + res;
	return res;
}

// never overwrites: "name.ext" becomes "name (1).ext"
static CMStringW uniquePath(const CMStringW &wszDir, const CMStringW &wszName)
{
	CMStringW res(wszDir + wszName);
	int idx = wszName.ReverseFind('.');
	CMStringW wszStem(idx > 0 ? wszName.Left(idx) : wszName), wszExt(idx > 0 ? wszName.Mid(idx) : CMStringW());
	for (int i = 1; _waccess(res, 0) == 0; i++)
		res.Format(L"%s%s (%d)%s", wszDir.c_str(), wszStem.c_str(), i, wszExt.c_str());
	return res;
}

/////////////////////////////////////////////////////////////////////////////////////////
// the list of transfers

KicqTransfer* CKicqProto::FtFind(const bytes_t &cookie)
{
	for (auto *t : m_arTransfers)
		if (t->cookie == cookie)
			return t;
	return nullptr;
}

bool CKicqProto::FtExists(KicqTransfer *t)
{
	return std::find(m_arTransfers.begin(), m_arTransfers.end(), t) != m_arTransfers.end();
}

void CKicqProto::FtRemove(KicqTransfer *t)
{
	{
		mir_cslock lck(m_csTransfers);
		auto it = std::find(m_arTransfers.begin(), m_arTransfers.end(), t);
		if (it != m_arTransfers.end())
			m_arTransfers.erase(it);
	}
	delete t;
}

// stops the running thread of a transfer: whatever it waits for fails at once
void CKicqProto::FtInterrupt(KicqTransfer *t)
{
	t->bCancelled = true;
	if (t->hConn)
		Netlib_Shutdown(t->hConn);
}

// the session has ended: the offers nobody answered yet cannot be answered anymore
void CKicqProto::FtDropPending()
{
	std::vector<KicqTransfer*> dropped;
	{
		mir_cslock lck(m_csTransfers);
		for (auto it = m_arTransfers.begin(); it != m_arTransfers.end();) {
			if (!(*it)->bStarted) {
				dropped.push_back(*it);
				it = m_arTransfers.erase(it);
			}
			else ++it;
		}
	}

	for (auto *t : dropped) {
		ProtoBroadcastAck(t->hContact, ACKTYPE_FILE, ACKRESULT_FAILED, t);
		delete t;
	}
}

void CKicqProto::FtCancelAll()
{
	mir_cslock lck(m_csTransfers);
	for (auto *t : m_arTransfers)
		FtInterrupt(t);
}

// the server has refused our offer (the peer is offline, for example)
bool CKicqProto::FtOfferRefused(uint32_t reqId, int code)
{
	mir_cslock lck(m_csTransfers);
	for (auto *t : m_arTransfers) {
		if (reqId != 0 && t->reqId == reqId) {
			debugLogA("file offer to %u failed, error %d", t->uin, code);
			FtInterrupt(t);
			return true;
		}
	}
	return false;
}

/////////////////////////////////////////////////////////////////////////////////////////
// the transfer connection

bool CKicqProto::FtConnect(KicqTransfer *t, const char *host, int port, int timeout)
{
	FtDisconnect(t);
	if (t->bCancelled)
		return false;

	debugLogA("file transfer: connecting to %s:%d", host, port);
	HNETLIBCONN hConn = Netlib_OpenConnection(m_hNetlibUser, host, port, timeout);
	if (hConn == nullptr) {
		debugLogA("file transfer: cannot connect to %s:%d", host, port);
		return false;
	}

	mir_cslock lck(m_csTransfers);
	t->hConn = hConn;
	return !t->bCancelled;
}

void CKicqProto::FtDisconnect(KicqTransfer *t)
{
	HNETLIBCONN hConn;
	{
		mir_cslock lck(m_csTransfers);
		hConn = t->hConn;
		t->hConn = nullptr;
	}
	if (hConn)
		Netlib_CloseHandle(hConn);
}

bool CKicqProto::FtWrite(KicqTransfer *t, const void *data, int len)
{
	auto *p = (const char *)data;
	while (len > 0) {
		if (t->bCancelled)
			return false;
		int n = Netlib_Send(t->hConn, p, min(len, FT_CHUNK), MSG_NODUMP);
		if (n <= 0)
			return false;
		p += n;
		len -= n;
	}
	return true;
}

// false as well when a redirect has arrived: the connection being read is not needed anymore
bool CKicqProto::FtRead(KicqTransfer *t, void *data, int len, int timeout)
{
	auto *p = (char *)data;
	time_t last = time(0);
	while (len > 0) {
		if (t->bCancelled || t->bRedirect)
			return false;

		NETLIBSELECT nls = {};
		nls.dwTimeout = 500;
		nls.hReadConns[0] = t->hConn;
		int ret = Netlib_Select(&nls);
		if (ret < 0)
			return false;
		if (ret == 0) {
			if (time(0) - last >= timeout) {
				debugLogA("file transfer: timed out");
				return false;
			}
			continue;
		}

		int n = Netlib_Recv(t->hConn, p, len, MSG_NODUMP);
		if (n <= 0)
			return false;
		p += n;
		len -= n;
		last = time(0);
	}
	return true;
}

// sends a command to the proxy
bool CKicqProto::FtProxySend(KicqTransfer *t, const bytes_t &packet)
{
	return FtWrite(t, packet.data(), (int)packet.size());
}

// reads one framed packet of the proxy, returns its command or -1
int CKicqProto::FtProxyRead(KicqTransfer *t, bytes_t &body, int timeout)
{
	uint8_t hdr[2];
	if (!FtRead(t, hdr, 2, timeout))
		return -1;

	int len = (hdr[0] << 8) | hdr[1];
	if (len < 10 || len > 1024)
		return -1;

	body.resize(len);
	if (!FtRead(t, &body[0], len, timeout))
		return -1;

	OscarReader r(body);
	if (r.u16() != PROXY_VERSION)
		return -1;

	int cmd = r.u16();
	if (cmd == PROXY_ERROR)
		debugLogA("file transfer: the proxy returned error %d", OscarReader(body, 10).u16());
	return cmd;
}

bool CKicqProto::FtAllocate(KicqTransfer *t, uint32_t &ip, int &port)
{
	CMStringA szProxy(FileProxyHost());
	if (szProxy.IsEmpty()) {
		debugLogA("file transfer: no proxy of our own");
		return false;
	}
	if (!FtConnect(t, szProxy, m_iFileProxyPort, 20))
		return false;
	if (!FtProxySend(t, OscarPackets::proxyAllocate(m_szUin, t->cookie)))
		return false;

	bytes_t body;
	if (FtProxyRead(t, body, FT_TIMEOUT) != PROXY_ALLOCATE_OK || body.size() < 16)
		return false;

	OscarReader r(body, 10);
	port = r.u16();
	ip = r.u32();
	return true;
}

// goes to the place the peer has named in its offer
bool CKicqProto::FtJoin(KicqTransfer *t)
{
	CMStringA szHost(FORMAT, "%u.%u.%u.%u", t->ip >> 24, (t->ip >> 16) & 255, (t->ip >> 8) & 255, t->ip & 255);

	if (!t->bPeerProxy) // a direct connection to the peer: no handshake
		return t->ip != 0 && FtConnect(t, szHost, t->port, 5);

	auto tryProxy = [&](const char *host, int port) {
		if (!FtConnect(t, host, port, 20))
			return false;
		if (!FtProxySend(t, OscarPackets::proxyJoin(m_szUin, t->port, t->cookie)))
			return false;
		bytes_t body;
		return FtProxyRead(t, body, FT_TIMEOUT) == PROXY_READY;
	};

	// the port of an offer is the TCP port of the proxy here; the old AOL proxy had it as a
	// mere ticket and listened elsewhere, hence the proxy of the options as the second chance
	if (t->ip != 0 && tryProxy(szHost, t->port))
		return true;
	CMStringA szOwn(FileProxyHost());
	return !szOwn.IsEmpty() && tryProxy(szOwn, m_iFileProxyPort);
}

/////////////////////////////////////////////////////////////////////////////////////////
// sending

void CKicqProto::SendFileThread(void *param)
{
	auto *t = (KicqTransfer *)param;

	bool bOk = FtSendFiles(t);
	FtDisconnect(t);

	debugLogA("file transfer to %u: %s", t->uin, bOk ? "success" : "failed");
	ProtoBroadcastAck(t->hContact, ACKTYPE_FILE, bOk ? ACKRESULT_SUCCESS : (t->bDenied ? ACKRESULT_DENIED : ACKRESULT_FAILED), t);
	FtRemove(t);
}

bool CKicqProto::FtSendFiles(KicqTransfer *t)
{
	ProtoBroadcastAck(t->hContact, ACKTYPE_FILE, ACKRESULT_CONNECTPROXY, t);

	uint32_t ip;
	int port;
	if (!FtAllocate(t, ip, port))
		return false;

	{
		mir_cslock lck(m_csPending);
		t->reqId = m_nextMsgReq++;
		if (m_nextMsgReq > 0x7FFFFFF0)
			m_nextMsgReq = 0x1000;
	}

	CMStringA szUin(FORMAT, "%u", t->uin);
	Send(OscarPackets::fileOffer(szUin, t->cookie, ip, port, T2Utf(t->wszName), (int)t->files.size(), t->totalSize, T2Utf(t->wszDescr), t->reqId));
	ProtoBroadcastAck(t->hContact, ACKTYPE_FILE, ACKRESULT_LISTENING, t);

	// waiting for the peer, who may also ask us to come to its proxy instead
	while (true) {
		bytes_t body;
		int cmd = FtProxyRead(t, body, FT_JOIN_TIMEOUT);
		if (cmd == PROXY_READY)
			break;
		if (!t->bRedirect)
			return false;

		t->bRedirect = false;
		if (FtJoin(t))
			break;
		return false;
	}

	ProtoBroadcastAck(t->hContact, ACKTYPE_FILE, ACKRESULT_CONNECTED, t);

	PROTOFILETRANSFERSTATUS fts = {};
	fts.hContact = t->hContact;
	fts.flags = PFTS_UNICODE | PFTS_SENDING;
	fts.totalFiles = (int)t->files.size();
	fts.totalBytes = t->totalSize;

	for (size_t i = 0; i < t->files.size(); i++)
		if (!FtSendOne(t, int(i), fts))
			return false;
	return true;
}

bool CKicqProto::FtSendOne(KicqTransfer *t, int idx, PROTOFILETRANSFERSTATUS &fts)
{
	const CMStringW &wszPath = t->files[idx];
	FILE *in = _wfopen(wszPath, L"rb");
	if (in == nullptr) {
		debugLogW(L"file transfer: cannot open %s", wszPath.c_str());
		return false;
	}

	std::vector<uint8_t> buf(FT_CHUNK);

	// the prompt carries the checksum of the whole file
	uint32_t sum = 0xFFFF0000, size = 0;
	while (size_t n = fread(buf.data(), 1, buf.size(), in)) {
		sum = oftChecksum(buf.data(), n, sum, (size & 1) != 0);
		size += (uint32_t)n;
	}
	rewind(in);

	int idxName = wszPath.ReverseFind('\\');
	CMStringW wszName(idxName == -1 ? wszPath : wszPath.Mid(idxName + 1));

	fts.currentFileNumber = idx;
	fts.szCurrentFile.w = (wchar_t *)wszPath.c_str();
	fts.currentFileSize = size;
	fts.currentFileProgress = 0;
	ProtoBroadcastAck(t->hContact, ACKTYPE_FILE, ACKRESULT_NEXTFILE, t);
	ProtoBroadcastAck(t->hContact, ACKTYPE_FILE, ACKRESULT_DATA, t, (LPARAM)&fts);

	bytes_t prompt = OscarPackets::oftPrompt(t->cookie, (int)t->files.size(), (int)t->files.size() - idx, t->totalSize, size, sum, wszName);
	bool bOk = FtWrite(t, prompt.data(), (int)prompt.size());

	bytes_t hdr;
	bOk = bOk && FtReadOft(t, hdr, OFT_ACK);

	DWORD dwLast = GetTickCount();
	uint32_t sent = 0;
	while (bOk && sent < size) {
		size_t n = fread(buf.data(), 1, min(buf.size(), size_t(size - sent)), in);
		if (n == 0 || !FtWrite(t, buf.data(), (int)n)) {
			bOk = false;
			break;
		}

		sent += (uint32_t)n;
		fts.totalProgress += n;
		fts.currentFileProgress = sent;
		if (sent == size || GetTickCount() - dwLast >= 250) {
			dwLast = GetTickCount();
			ProtoBroadcastAck(t->hContact, ACKTYPE_FILE, ACKRESULT_DATA, t, (LPARAM)&fts);
		}
	}
	fclose(in);

	return bOk && FtReadOft(t, hdr, OFT_DONE);
}

// reads OFT2 headers until the wanted type comes
bool CKicqProto::FtReadOft(KicqTransfer *t, bytes_t &hdr, int wanted)
{
	while (true) {
		char start[6];
		if (!FtRead(t, start, sizeof(start), FT_TIMEOUT))
			return false;
		if (memcmp(start, "OFT2", 4)) {
			debugLogA("file transfer: not an OFT2 header");
			return false;
		}

		int len = ((uint8_t)start[4] << 8) | (uint8_t)start[5];
		if (len < 256 || len > 2048) {
			debugLogA("file transfer: an OFT2 header of %d bytes", len);
			return false;
		}

		hdr.assign(start, sizeof(start));
		hdr.resize(len);
		if (!FtRead(t, &hdr[sizeof(start)], len - (int)sizeof(start), FT_TIMEOUT))
			return false;

		int type = OscarReader(hdr, OFT_TYPE).u16();
		if (type == wanted)
			return true;
		debugLogA("file transfer: skipping OFT2 type %04x", type);
	}
}

HANDLE CKicqProto::SendFile(MCONTACT hContact, const wchar_t *szDescription, wchar_t **ppszFiles)
{
	uint32_t uin = getDword(hContact, "UIN");
	if (!m_bOnline || uin == 0 || ppszFiles == nullptr || FileProxyHost().IsEmpty())
		return nullptr;

	auto *t = new KicqTransfer();
	uint64_t total = 0;
	for (int i = 0; ppszFiles[i]; i++) {
		struct _stat64 st;
		if (_wstat64(ppszFiles[i], &st) || (st.st_mode & _S_IFDIR))
			continue;
		t->files.push_back(ppszFiles[i]);
		total += st.st_size;
	}

	// OFT2 has 32 bit sizes
	if (t->files.empty() || total > 0xFFFFFFFFull) {
		delete t;
		return nullptr;
	}

	char cookie[8];
	Utils_GetRandom(cookie, sizeof(cookie));

	t->hContact = hContact;
	t->uin = uin;
	t->bSending = t->bStarted = true;
	t->cookie.assign(cookie, sizeof(cookie));
	t->totalSize = (uint32_t)total;
	t->wszDescr = szDescription;
	int idx = t->files[0].ReverseFind('\\');
	t->wszName = idx == -1 ? t->files[0] : t->files[0].Mid(idx + 1);
	{
		mir_cslock lck(m_csTransfers);
		m_arTransfers.push_back(t);
	}

	ForkThread(&CKicqProto::SendFileThread, t);
	return t;
}

/////////////////////////////////////////////////////////////////////////////////////////
// receiving

void CKicqProto::RecvFileThread(void *param)
{
	auto *t = (KicqTransfer *)param;

	bool bOk = FtRecvFiles(t);
	FtDisconnect(t);

	debugLogA("file transfer from %u: %s", t->uin, bOk ? "success" : "failed");
	ProtoBroadcastAck(t->hContact, ACKTYPE_FILE, bOk ? ACKRESULT_SUCCESS : (t->bDenied ? ACKRESULT_DENIED : ACKRESULT_FAILED), t);
	FtRemove(t);
}

bool CKicqProto::FtRecvFiles(KicqTransfer *t)
{
	CMStringA szUin(FORMAT, "%u", t->uin);

	ProtoBroadcastAck(t->hContact, ACKTYPE_FILE, t->bPeerProxy ? ACKRESULT_CONNECTPROXY : ACKRESULT_CONNECTING, t);
	if (FtJoin(t))
		Send(OscarPackets::fileAccept(szUin, t->cookie));
	else {
		// the sender cannot be reached: it is invited to our proxy, no accept is needed then
		t->bRedirect = false;
		uint32_t ip;
		int port;
		if (!FtAllocate(t, ip, port))
			return false;

		Send(OscarPackets::fileRedirect(szUin, t->cookie, ip, port));

		bytes_t body;
		if (FtProxyRead(t, body, FT_JOIN_TIMEOUT) != PROXY_READY)
			return false;
	}
	t->bRedirect = false;

	ProtoBroadcastAck(t->hContact, ACKTYPE_FILE, ACKRESULT_CONNECTED, t);

	CMStringW wszDir(t->wszSavePath);
	if (!wszDir.IsEmpty() && wszDir[wszDir.GetLength() - 1] != '\\')
		wszDir.AppendChar('\\');
	CreateDirectoryTreeW(wszDir);

	PROTOFILETRANSFERSTATUS fts = {};
	fts.hContact = t->hContact;
	fts.flags = PFTS_UNICODE;
	fts.totalFiles = t->fileCount;
	fts.totalBytes = t->totalSize;
	fts.szWorkingDir.w = wszDir.GetBuffer();

	for (int idx = 0;; idx++) {
		bytes_t hdr;
		if (!FtReadOft(t, hdr, OFT_PROMPT))
			return false;
		if (!FtRecvOne(t, idx, wszDir, hdr, fts))
			return false;
		if (OscarReader(hdr, OFT_FILES_LEFT).u16() <= 1)
			return true;
	}
}

// hdr comes as the prompt and is sent back as the ack and as the "done"
bool CKicqProto::FtRecvOne(KicqTransfer *t, int idx, const CMStringW &wszDir, bytes_t &hdr, PROTOFILETRANSFERSTATUS &fts)
{
	uint32_t size = readBE32(hdr, OFT_SIZE);

	CMStringW wszName(t->wszName);
	if (t->fileCount != 1 || wszName.IsEmpty()) {
		bytes_t raw(hdr.substr(OFT_NAME));
		if (OscarReader(hdr, OFT_ENCODING).u16() == 2) {
			size_t end = 0;
			while (end + 1 < raw.size() && (raw[end] || raw[end + 1]))
				end += 2;
			wszName = OscarText::fromUcs2(raw.substr(0, end));
		}
		else wszName = OscarText::textOrCp1251(raw.substr(0, raw.find('\0')));
	}

	CMStringW wszPath(uniquePath(wszDir, sanitizeFileName(wszName)));
	FILE *out = _wfopen(wszPath, L"wb");
	if (out == nullptr) {
		debugLogW(L"file transfer: cannot create %s", wszPath.c_str());
		return false;
	}

	fts.currentFileNumber = idx;
	fts.szCurrentFile.w = wszPath.GetBuffer();
	fts.currentFileSize = size;
	fts.currentFileProgress = 0;
	ProtoBroadcastAck(t->hContact, ACKTYPE_FILE, ACKRESULT_NEXTFILE, t);
	ProtoBroadcastAck(t->hContact, ACKTYPE_FILE, ACKRESULT_DATA, t, (LPARAM)&fts);

	hdr[OFT_TYPE] = char(OFT_ACK >> 8);
	hdr[OFT_TYPE + 1] = char(OFT_ACK & 0xFF);
	hdr.replace(OFT_COOKIE, 8, t->cookie);
	bool bOk = FtWrite(t, hdr.data(), (int)hdr.size());

	std::vector<uint8_t> buf(FT_CHUNK);
	DWORD dwLast = GetTickCount();
	uint32_t received = 0, sum = 0xFFFF0000;
	while (bOk && received < size) {
		int n = (int)min(buf.size(), size_t(size - received));
		if (!FtRead(t, buf.data(), n, FT_TIMEOUT) || fwrite(buf.data(), 1, n, out) != (size_t)n) {
			bOk = false;
			break;
		}

		sum = oftChecksum(buf.data(), n, sum, (received & 1) != 0);
		received += n;
		fts.totalProgress += n;
		fts.currentFileProgress = received;
		if (received == size || GetTickCount() - dwLast >= 250) {
			dwLast = GetTickCount();
			ProtoBroadcastAck(t->hContact, ACKTYPE_FILE, ACKRESULT_DATA, t, (LPARAM)&fts);
		}
	}
	fclose(out);

	if (bOk) {
		if (readBE32(hdr, 0x28) != sum)
			debugLogA("file transfer: the checksum differs from the one in the prompt");

		hdr[OFT_TYPE + 1] = char(OFT_DONE & 0xFF);
		writeBE32(hdr, OFT_RECEIVED, received);
		writeBE32(hdr, OFT_RECV_SUM, sum);
		bOk = FtWrite(t, hdr.data(), (int)hdr.size());
	}

	if (!bOk)
		_wremove(wszPath);
	return bOk;
}

// the channel 2 ICBM with the file capability
void CKicqProto::HandleFileRendezvous(uint32_t uin, int msgType, const bytes_t &cookie, OscarReader &r)
{
	CMStringA szUin(FORMAT, "%u", uin);
	OscarTlvList tlvs(r);

	if (msgType == 1) { // the peer has refused or cancelled
		KicqTransfer *pending = nullptr;
		{
			mir_cslock lck(m_csTransfers);
			auto *t = FtFind(cookie);
			if (t == nullptr || t->uin != uin)
				return;

			t->bDenied = t->bSending;
			if (t->bStarted)
				FtInterrupt(t);
			else {
				pending = t;
				m_arTransfers.erase(std::find(m_arTransfers.begin(), m_arTransfers.end(), t));
			}
		}
		if (pending) {
			ProtoBroadcastAck(pending->hContact, ACKTYPE_FILE, ACKRESULT_FAILED, pending);
			delete pending;
		}
		return;
	}

	if (msgType != 0)
		return; // an accept says nothing new: READY from the proxy has told it already

	auto ipOf = [&](int type) { auto *p = tlvs.find(type); return p ? p->u32() : 0; };

	uint32_t ip = ipOf(2), clientIp = ipOf(3), verifiedIp = ipOf(4);
	auto *pPort = tlvs.find(5);
	int port = pPort ? pPort->u16() : 0;
	bool bProxy = tlvs.has(0x10);

	{
		mir_cslock lck(m_csTransfers);
		if (auto *t = FtFind(cookie)) {
			// the same cookie again: the peer asks to go somewhere else
			if (t->uin == uin && t->bStarted && port != 0) {
				t->bPeerProxy = bProxy;
				t->ip = bProxy ? ip : (verifiedIp ? verifiedIp : clientIp);
				t->port = port;
				t->bRedirect = true;
			}
			return;
		}
	}

	auto *pInfo = tlvs.find(0x2711);
	if (pInfo == nullptr || pInfo->data.size() < 9)
		return;

	OscarReader info(pInfo->data);
	info.u16();                             // one file or several
	int count = info.u16();
	uint32_t size = info.u32();
	bytes_t rawName = info.rest();
	rawName = rawName.substr(0, rawName.find('\0'));

	auto *pCharset = tlvs.find(0x2712);
	CMStringW wszName(pCharset && !stricmp(pCharset->data.c_str(), "utf-8") ? OscarText::fromUtf8(rawName) : OscarText::decodeGuess(rawName));

	CMStringW wszDescr;
	if (auto *pDescr = tlvs.find(0x0C)) {
		auto *pDescrSet = tlvs.find(0x0D);
		wszDescr = OscarText::cleanup(pDescrSet && !stricmp(pDescrSet->data.c_str(), "utf-8") ? OscarText::fromUtf8(pDescr->data) : OscarText::decodeGuess(pDescr->data));
	}

	MCONTACT hContact = FindContact(uin);
	if (hContact == 0)
		hContact = CreateContact(uin, true);
	{
		mir_cslock lck(m_csRoster);
		AddUser(uin, hContact);
	}

	auto *t = new KicqTransfer();
	t->hContact = hContact;
	t->uin = uin;
	t->cookie = cookie;
	t->wszName = wszName;
	t->totalSize = size;
	t->fileCount = max(count, 1);
	t->bPeerProxy = bProxy;
	t->ip = bProxy ? ip : (verifiedIp ? verifiedIp : clientIp);
	t->port = port;
	{
		mir_cslock lck(m_csTransfers);
		m_arTransfers.push_back(t);
	}

	debugLogA("file offer from %u: %d file(s), %u bytes, proxy %d", uin, count, size, bProxy);

	DB::EventInfo dbei;
	dbei.iTimestamp = time(0);
	DB::FILE_BLOB blob(t, T2Utf(wszName), T2Utf(wszDescr));
	blob.setSize(size);
	ProtoChainRecvFile(hContact, blob, dbei);
}

HANDLE CKicqProto::FileAllow(MCONTACT, HANDLE hTransfer, const wchar_t *szPath)
{
	auto *t = (KicqTransfer *)hTransfer;
	{
		mir_cslock lck(m_csTransfers);
		if (!FtExists(t) || t->bStarted)
			return nullptr;
		t->bStarted = true;
		t->wszSavePath = szPath;
	}

	ForkThread(&CKicqProto::RecvFileThread, t);
	return hTransfer;
}

int CKicqProto::FileDeny(MCONTACT hContact, HANDLE hTransfer, const wchar_t *)
{
	return FileCancel(hContact, hTransfer);
}

int CKicqProto::FileCancel(MCONTACT, HANDLE hTransfer)
{
	auto *t = (KicqTransfer *)hTransfer;
	bytes_t cookie;
	uint32_t uin;
	{
		mir_cslock lck(m_csTransfers);
		if (!FtExists(t))
			return 1;

		cookie = t->cookie;
		uin = t->uin;
		if (t->bStarted)
			FtInterrupt(t);
		else {
			m_arTransfers.erase(std::find(m_arTransfers.begin(), m_arTransfers.end(), t));
			delete t;
		}
	}

	CMStringA szUin(FORMAT, "%u", uin);
	Send(OscarPackets::fileCancel(szUin, cookie));
	return 0;
}
