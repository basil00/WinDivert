;/*
; * windivert_log.mc
; * (C) 2019, all rights reserved,
; *
; * This file is part of WinDivert.
; *
; * WinDivert is free software: you can redistribute it and/or modify it under
; * the terms of the GNU Lesser General Public License as published by the
; * Free Software Foundation, either version 3 of the License, or (at your
; * option) any later version.
; *
; * This program is distributed in the hope that it will be useful, but
; * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
; * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
; * License for more details.
; *
; * You should have received a copy of the GNU Lesser General Public License
; * along with this program.  If not, see <http://www.gnu.org/licenses/>.
; *
; * WinDivert is free software; you can redistribute it and/or modify it under
; * the terms of the GNU General Public License as published by the Free
; * Software Foundation; either version 2 of the License, or (at your option)
; * any later version.
; * 
; * This program is distributed in the hope that it will be useful, but
; * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
; * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
; * for more details.
; * 
; * You should have received a copy of the GNU General Public License along
; * with this program; if not, write to the Free Software Foundation, Inc., 51
; * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
; */

MessageIdTypedef=NTSTATUS

SeverityNames = (
    Success       = 0x0:STATUS_SEVERITY_SUCCESS
    Informational = 0x1:STATUS_SEVERITY_INFORMATIONAL
    Warning       = 0x2:STATUS_SEVERITY_WARNING
    Error         = 0x3:STATUS_SEVERITY_ERROR
)

FacilityNames = (
    System    = 0x0:FACILITY_SYSTEM
    Runtime   = 0x2:FACILITY_RUNTIME
    Stubs     = 0x3:FACILITY_STUBS
    Io        = 0x4:FACILITY_IO_ERROR_CODE
    WinDivert = 0x574:FACILITY_WINDIVERT
)

MessageId=0x312D
Facility=WinDivert
Severity=Informational
SymbolicName=WINDIVERT_INFO_EVENT
Language=English
%2 %3 (processId=%4)
.

