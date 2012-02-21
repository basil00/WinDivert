!IF "$(_BUILDARCH)" == "x86"
CPU=i386
!ELSE
CPU=$(_BUILDARCH)
!ENDIF

$(TARGETPATH)\$(CPU)\WinDivert.inf: divert.inf
	copy /y divert.inf $@
$(TARGETPATH)\$(CPU)\WdfCoInstaller01009.dll:
	copy /y $(BASEDIR)\redist\wdf\$(_BUILDARCH)\WdfCoInstaller01009.dll $@
