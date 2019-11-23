package windows

import "fmt"

func User32Hooks(emu *WinEmulator) {
	emu.AddHook("", "GetForegroundWindow", &Hook{
		Parameters: []string{},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, 0x1)(emu, in)
		},
	})
	emu.AddHook("", "GetWindowRect", &Hook{Parameters: []string{"hWnd", "lpRect"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "CreateDialogParamA", &Hook{Parameters: []string{"hInstance", "a:lpTemplateName", "hWndParent", "lpDialogFunc", "dwInitParam"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "FindWindowA", &Hook{
		Parameters: []string{"a:lpClassName", "lpWindowName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			ret := uint64(0x1)
			fmt.Printf("in.Hook.Values[0]: %T\n", in.Hook.Values[0])
			fmt.Printf("in.Hook.Values[0]: %v\n", in.Hook.Values[0])
			if in.Hook.Values[0] == "DIABLO" {
				ret = 0x0
			}
			return SkipFunctionStdCall(true, ret)(emu, in)
		},
	})
	emu.AddHook("", "MapWindowPoints", &Hook{Parameters: []string{"hWndFrom", "hWndTo", "lpPoints", "cPoints"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "NtUserGetThreadState", &Hook{
		Parameters: []string{"Routine"},
	})
	emu.AddHook("", "SendMessageA", &Hook{Parameters: []string{"hWnd", "Msg", "wParam", "lParam"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "SetCursorPos", &Hook{Parameters: []string{"X", "Y"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "SetFocus", &Hook{
		Parameters: []string{"hWnd"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, 0x01)(emu, in)
		},
	})
	emu.AddHook("", "SetForegroundWindow", &Hook{
		Parameters: []string{"hWnd"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, 0x01)(emu, in)
		},
	})
	emu.AddHook("", "SetTimer", &Hook{Parameters: []string{"hWnd", "nIDEvent", "uElapse", "lpTimerFunc"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "ShowCursor", &Hook{
		Parameters: []string{"bShow"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, in.Args[0])(emu, in)
		},
	})
	emu.AddHook("", "ShowWindow", &Hook{Parameters: []string{"hWnd", "nCmdShow"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "wsprintfA", &Hook{
		Parameters: []string{"lpstr", "a:lpcstr"},
	})
	emu.AddHook("", "wvsprintfA", &Hook{
		Parameters: []string{"lpstr", "a:lpcstr", "arglist"},
	})
}
