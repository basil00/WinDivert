$(TARGETPATH)\$(_BUILDARCH)\divert.inf: divert.inf
	copy /y divert.inf $@
$(TARGETPATH)\$(_BUILDARCH)\WdfCoInstaller01009.dll:
	copy /y $(BASEDIR)\redist\wdf\$(_BUILDARCH)\WdfCoInstaller01009.dll $@
