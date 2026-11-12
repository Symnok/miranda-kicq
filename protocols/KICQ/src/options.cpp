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

#include "stdafx.h"

class CKicqAccountDlg : public CKicqDlgBase
{
	CCtrlEdit edtUin, edtPassword, edtServer, edtPort, edtGroup, edtFileProxy, edtFileProxyPort;
	CCtrlCombo cmbService;

	// A preset fills the connection fields in and locks them; "Other server" leaves them to the user.
	void ShowService(bool bFill)
	{
		int idx = cmbService.GetCurSel();
		if (idx < 0 || idx >= g_serviceCount)
			return;

		const KicqService &s = g_services[idx];
		bool bCustom = s.server[0] == 0;
		if (!bCustom && bFill) {
			edtServer.SetTextA(s.server);
			edtPort.SetInt(s.port);
			edtFileProxy.SetTextA(s.fileProxy);
			edtFileProxyPort.SetInt(s.fileProxyPort);
		}
		edtServer.Enable(bCustom);
		edtPort.Enable(bCustom);
		edtFileProxy.Enable(bCustom);
		edtFileProxyPort.Enable(bCustom);
	}

	void onSelChange_Service(CCtrlCombo *)
	{
		ShowService(true);
		NotifyChange();
	}

public:
	CKicqAccountDlg(CKicqProto *ppro, int iDlgId) :
		CKicqDlgBase(ppro, iDlgId),
		edtUin(this, IDC_UIN),
		edtPassword(this, IDC_PASSWORD),
		edtServer(this, IDC_SERVER),
		edtPort(this, IDC_PORT),
		edtGroup(this, IDC_GROUP),
		edtFileProxy(this, IDC_FILEPROXY),
		edtFileProxyPort(this, IDC_FILEPROXY_PORT),
		cmbService(this, IDC_SERVICE)
	{
		cmbService.OnSelChanged = Callback(this, &CKicqAccountDlg::onSelChange_Service);
		CreateLink(edtUin, "UIN", DBVT_DWORD, 0);
		CreateLink(edtPassword, "Password", L"");
		CreateLink(edtServer, ppro->m_wszServer);
		CreateLink(edtPort, ppro->m_iPort);
		CreateLink(edtGroup, ppro->m_wszDefaultGroup);
		CreateLink(edtFileProxy, ppro->m_wszFileProxy);
		CreateLink(edtFileProxyPort, ppro->m_iFileProxyPort);
	}

	bool OnInitDialog() override
	{
		// the XOR login of that ICQ era only uses the first 8 characters
		edtPassword.SendMsg(EM_LIMITTEXT, 8, 0);
		edtUin.SendMsg(EM_LIMITTEXT, 10, 0);

		CMStringA szKey(m_proto->ServiceKey());
		for (int i = 0; i < g_serviceCount; i++) {
			cmbService.AddString(TranslateW(g_services[i].name), i);
			if (szKey == g_services[i].key)
				cmbService.SetCurSel(i);
		}
		if (cmbService.GetCurSel() < 0)
			cmbService.SetCurSel(g_serviceCount - 1);
		ShowService(true);
		return true;
	}

	bool OnApply() override
	{
		int idx = cmbService.GetCurSel();
		if (idx < 0 || idx >= g_serviceCount)
			return true;

		const KicqService &s = g_services[idx];
		m_proto->setString("Service", s.key);
		if (s.server[0]) {
			m_proto->m_wszServer = _A2T(s.server);
			m_proto->m_iPort = s.port;
			m_proto->m_wszFileProxy = _A2T(s.fileProxy);
			m_proto->m_iFileProxyPort = s.fileProxyPort;
		}
		return true;
	}
};

MWindow CKicqProto::OnCreateAccMgrUI(MWindow hwndParent)
{
	auto *pDlg = new CKicqAccountDlg(this, IDD_ACCMGRUI);
	pDlg->SetParent(hwndParent);
	pDlg->Show();
	return pDlg->GetHwnd();
}

int CKicqProto::OnOptionsInit(WPARAM wParam, LPARAM)
{
	OPTIONSDIALOGPAGE odp = {};
	odp.flags = ODPF_UNICODE;
	odp.szGroup.w = LPGENW("Network");
	odp.szTitle.w = m_tszUserName;
	odp.position = 1;
	odp.pDialog = new CKicqAccountDlg(this, IDD_OPTIONS);
	g_plugin.addOptions(wParam, &odp);
	return 0;
}
