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

CMPlugin g_plugin;

PLUGININFOEX pluginInfoEx =
{
	sizeof(PLUGININFOEX),
	__PLUGIN_NAME,
	PLUGIN_MAKE_VERSION(__MAJOR_VERSION, __MINOR_VERSION, __RELEASE_NUM, __BUILD_NUM),
	__DESCRIPTION,
	__AUTHOR,
	__COPYRIGHT,
	__AUTHORWEB,
	UNICODE_AWARE,
	// {2F8D4A6C-91B3-4E57-A0C8-6B1E3D95F27A}
	{ 0x2f8d4a6c, 0x91b3, 0x4e57, { 0xa0, 0xc8, 0x6b, 0x1e, 0x3d, 0x95, 0xf2, 0x7a } }
};

CMPlugin::CMPlugin() :
	ACCPROTOPLUGIN<CLogonChatProto>("OSCAR-logon.chat", pluginInfoEx)
{
	SetUniqueId("UIN");
}

/////////////////////////////////////////////////////////////////////////////////////////

extern "C" __declspec(dllexport) const MUUID MirandaInterfaces[] = { MIID_PROTOCOL, MIID_LAST };

/////////////////////////////////////////////////////////////////////////////////////////

static IconItem iconList[] =
{
	{ LPGEN("Protocol icon"), "main", IDI_LOGONCHAT }
};

int CMPlugin::Load()
{
	registerIcon("Protocols/OSCAR-logon.chat", iconList, "LogonChat");
	return 0;
}
