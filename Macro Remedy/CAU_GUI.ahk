#Persistent
#SingleInstance force



SetTitleMatchMode, 2

Loop
{
    WinWaitActive, ahk_exe aruser.exe
    IfWinActive, ahk_exe aruser.exe
    {
        Gui +LastFound
        hWnd := WinExist()
        Gui, Add, Button, x10 y10 w100 h30 gButton1, Alba
        Gui, Add, Button, x10 y50 w100 h30 gButton2, @DRIANO
        Gui, Add, Button, x10 y90 w100 h30 gButton3, Credenciales
        Gui, Add, Button, x10 y130 w100 h30 gButton4, Ministerio
        Gui, Show, w120 h170, Números
        Break
    }
}


return

tlf()
{
    MsgBox, 4,, ¿Tiene teléfono en campo Remedy?
    IfMsgBox, Yes
    {
        Send, {TAB 4}
    }
    IfMsgBox, No
    {
        InputBox, phone, Teléfono, (Teléfono del usuario)
        Send, {TAB 4}
        Send, %phone%
    }
    Return
}


Button1:
    Run, PowerShell.exe -ExecutionPolicy Bypass -File "C:\Users\CAU.LAP\AppData\Roaming\AR System\HOME\ARCmds\Alba.ps1",, Hide
    SetTitleMatchMode, 2
    WinActivate, ahk_exe aruser.exe
    Send, ^i 
    Send, {TAB 2}{End}{Enter}
return


Button2:
    SetTitleMatchMode, 2
    WinActivate, ahk_exe aruser.exe
    tlf()
    Send, {TAB 23}{Right}{TAB 2}NUEVO ADRIANO{TAB}Se recibe llamada relacionada con {@}driano. Se comprueba que no esta relacionado con puesto de trabajo. Se realiza transfer de llamada para su gestion.{TAB 6}{Down}{TAB 34}NUEVO ADRIANO{TAB 3}Se realiza transfer de llamada a CA {@}driano para su gesti{ó}n. Se cierra ticket.^{enter}{Enter}
    Send, !a {Down 9}{Right}{Enter}{TAB 12}{Right 2}{TAB 5}{Enter 3}
    Send, !a {Down 9}{Right}{Enter}{TAB 12}{Right 2}{TAB 6}{Enter}Se recibe llamada relacionada con {@}driano. Se comprueba que no esta relacionado con puesto de trabajo. Se realiza transfer de llamada para su gestion. Se cierra ticket.{Tab}{Enter}
    SetTitleMatchMode, 2
    WinActivate, ahk_exe aruser.exe
   
Return


Button3:
    Gui, New, +AlwaysOnTop
    Gui, Add, Button, x10 y10 w100 h30 gButton3_1, AD
    Gui, Add, Button, x10 y50 w100 h30 gButton3_2, Correo
    Gui, Add, Button, x10 y90 w100 h30 gButton3_3, Arconte
    Gui, Add, Button, x10 y130 w100 h30 gButton3_4, Temis
    Gui, Show, w215 h220, Botón 3 - Submenú
return

Button3_1:
    SetTitleMatchMode, 2
    WinActivate, ahk_exe aruser.exe
    WinWaitActive, ahk_exe aruser.exe
    ControlSend, , 3.1, ahk_exe aruser.exe
    Gui, Destroy
return

Button3_2:
    SetTitleMatchMode, 2
    WinActivate, ahk_exe aruser.exe
    WinWaitActive, ahk_exe aruser.exe
    ControlSend, , 3.2, ahk_exe aruser.exe
    Gui, Destroy
return

Button3_3:
    SetTitleMatchMode, 2
    WinActivate, ahk_exe aruser.exe
    WinWaitActive, ahk_exe aruser.exe
    ControlSend, , 3.3, ahk_exe aruser.exe
    Gui, Destroy
return

Button3_4:
    SetTitleMatchMode, 2
    WinActivate, ahk_exe aruser.exe
    WinWaitActive, ahk_exe aruser.exe
    ControlSend, , 3.4, ahk_exe aruser.exe
    Gui, Destroy
return

Button4:
    SetTitleMatchMode, 2
    WinActivate, ahk_exe aruser.exe
    WinWaitActive, ahk_exe aruser.exe
    ControlSend, , 4, ahk_exe aruser.exe
return
