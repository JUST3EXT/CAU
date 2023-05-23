#SingleInstance, Force
SendMode Input
SetWorkingDir, %A_ScriptDir%

Esc::Reload
Return

pass:= ""
progra:=""

screen()
{
    WinActivate, ahk_exe aruser.exe
    WinWaitActive, ahk_exe aruser.exe
}

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
}


password()
{
    InputBox, pass, Password, (Nueva password)
}

app()
{
    InputBox, progra, Programa, (Programa al que vas a cambiar pass)
}

#1::
    Run, PowerShell.exe -ExecutionPolicy Bypass -File "C:\Users\CAU.LAP\AppData\Roaming\AR System\HOME\ARCmds\Alba.ps1",, Hide
    WinActivate, [ BMC Remedy User - [Página de inicio (Buscar)]]
    Send, ^i 
    Send, {TAB 2}{End}{Enter}
Return

#2::
    screen()
    tlf()
    Send, {TAB 23}{Right}{TAB 2}NUEVO ADRIANO{TAB}Se recibe llamada relacionada con {@}driano. Se comprueba que no esta relacionado con puesto de trabajo. Se realiza transfer de llamada para su gestion.{TAB 6}{Down}{TAB 34}NUEVO ADRIANO{TAB 3}Se realiza transfer de llamada a CA {@}driano para su gesti{ó}n. Se cierra ticket.^{enter}{Enter}
    Send, !a {Down 9}{Right}{Enter}{TAB 12}{Right 2}{TAB 5}{Enter 3}
    Send, !a {Down 9}{Right}{Enter}{TAB 12}{Right 2}{TAB 6}{Enter}Se recibe llamada relacionada con {@}driano. Se comprueba que no esta relacionado con puesto de trabajo. Se realiza transfer de llamada para su gestion. Se cierra ticket.{Tab}{Enter}
Return

#3::
    screen()
    pass:= ""
    progra:= ""
    tlf()
    Sleep, 1000
    password()
    app()
    Send, {TAB 36} %pass%
    Send, {TAB 25}{Right}{TAB 2}GESTION USUARIOS{TAB}
    Send, %progra%. Usuario no recuerda su contrase{U+00F1}a{TAB}CONTRASE{ASC 165}AS{TAB 2}Se cambia contrase{U+00F1}a del usuario{TAB 2}-
    Send, ^{enter}{Enter}
    Send, !a {Down 9}{Right}{Enter}{TAB 12}{Right 2}{TAB 5}{Enter 3}
    Send, !a {Down 9}{Right}{Enter}{TAB 12}{Right 2}{TAB 6}{Enter}
    Send, Se modifica la contrase{U+00F1}a campo Remedy
    Send, {Tab}{Enter}
Return

#4::
    tlf()
    Sleep, 1000
    password()
    Send, {TAB 36} %pass%
    Send, {TAB 25}{Right}{TAB 2}GESTION USUARIOS{TAB}
    Send, Correo. Usuario no recuerda su contrase{U+00F1}a{TAB}CONTRASE{ASC 165}AS{TAB 2}Se cambia contrase{U+00F1}a del usuario{TAB 2}-
    Send, ^{enter}{Enter}
    Send, !a {Down 9}{Right}{Enter}{TAB 12}{Right 2}{TAB 5}{Enter 3}
    Send, !a {Down 9}{Right}{Enter}{TAB 12}{Right 2}{TAB 6}{Enter}
    Send, Se modifica la contrase{U+00F1}a campo Remedy
    Send, {Tab}{Enter}
Return

#5::
    screen()
    tlf()
    Send, {TAB 23}{Right}{TAB 2}COMUNICACIONES{TAB}Se recibe llamada relacionada con servicio no relacionado con el CIUS. Se comprueba que no esta relacionado con puesto de trabajo. Se comunica n{ú}mero del servicio correspondiente{TAB 6}{Down}{TAB 34}COMUNICACIONES{TAB 3}Se recibe llamada relacionada con servicio no relacionado con el CIUS. Se comprueba que no esta relacionado con puesto de trabajo. Se comunica n{ú}mero del servicio correspondiente^{enter}{Enter}
    Send, !a {Down 9}{Right}{Enter}{TAB 12}{Right 2}{TAB 5}{Enter 3}
    Send, !a {Down 9}{Right}{Enter}{TAB 12}{Right 2}{TAB 6}{Enter}Se recibe llamada relacionada con servicio no relacionado con el CIUS. Se comprueba que no esta relacionado con puesto de trabajo. Se comunica n{ú}mero del servicio correspondiente. Se cierra ticket.{Tab}{Enter}
Return

#6::
    screen()
    tlf()
    Send, {TAB 23}{Right}{TAB 2}PUESTO DE TRABAJO{TAB}Usuaria llama comentando que su equipo presenta lentitud, los programas no funcionan correctamente.{TAB}SOFTWARE{TAB 2} Se realiza bateria de prubeas y se reincia el equipo, se comprueba que funciona correctamente{TAB 2}-
    Send, ^{enter}{Enter}
    Send, !a {Down 9}{Right}{Enter}{TAB 12}{Right 2}{TAB 5}{Enter 3}
    Send, !a {Down 9}{Right}{Enter}{TAB 12}{Right 2}{TAB 6}{Enter}Se realiza batería de pruebas y funciona correctamente. Se cierra ticket.{Tab}{Enter}
Return