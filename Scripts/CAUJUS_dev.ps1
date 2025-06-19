# Script: CAUJUS_dev.ps1
# Propósito: Proporciona una utilidad controlada por menús para diversas tareas de soporte de TI de CAU.
# Versión: 1.0.0 (Migración Inicial a PowerShell)
# Última Modificación: $(Get-Date -Format 'yyyy-MM-dd')

# --- Variables de Configuración ---
$ConfigRemoteLogDir = "\\iusnas05\SIJ\CAU-2012\logs"
$ConfigSoftwareBasePath = "\\iusnas05\DDPP\COMUN\Aplicaciones Corporativas"
$ConfigDriverBasePath = "\\iusnas05\DDPP\COMUN\_DRIVERS\lectores tarjetas"

$ConfigIslMsiPath = Join-Path $ConfigSoftwareBasePath "isl.msi"
$ConfigFnmtConfigExe = Join-Path $ConfigSoftwareBasePath "Configurador_FNMT_5.0.0_64bits.exe"
$ConfigAutoFirmaExe = Join-Path $ConfigSoftwareBasePath "AutoFirma_64_v1_8_3_installer.exe"
$ConfigAutoFirmaMsi = Join-Path $ConfigSoftwareBasePath "AutoFirma_v1_6_0_JAv05_installer_64.msi" # Comprobar si esto todavía es necesario junto al .exe
$ConfigChromeMsiPath = Join-Path $ConfigSoftwareBasePath "chrome.msi"
$ConfigLibreOfficeMsiPath = Join-Path $ConfigSoftwareBasePath "LibreOffice.msi"

$ConfigDriverPctPath = Join-Path $ConfigDriverBasePath "PCT-331_V8.52\SCR3xxx_V8.52.exe"
$ConfigDriverSatellitePath = Join-Path $ConfigDriverBasePath "satellite pro a50c169 smartcard\smr-20151028103759\TCJ0023500B.exe"

$ConfigUrlMiCuentaJunta = "https://micuenta.juntadeandalucia.es/micuenta/es.juntadeandalucia.micuenta.servlets.LoginInicial"
$ConfigUrlFnmtSolicitar = "https://www.sede.fnmt.gob.es/certificados/persona-fisica/obtener-certificado-software/solicitar-certificado"
$ConfigUrlFnmtRenovar = "https://www.sede.fnmt.gob.es/certificados/persona-fisica/renovar/solicitar-renovacion"
$ConfigUrlFnmtDescargar = "https://www.sede.fnmt.gob.es/certificados/persona-fisica/obtener-certificado-software/descargar-certificado"

$ConfigScriptVersion = "1.0.0" # Migración PowerShell
# --- Fin de Variables de Configuración ---

# --- Variables Globales del Script ---
$GlobalAdUser = $null
$GlobalUserProfileName = $env:USERNAME
$GlobalCurrentHostname = $env:COMPUTERNAME
$GlobalLogDir = Join-Path $env:TEMP "CAUJUS_Logs"
$GlobalLogFile = "" # Se establecerá después de la entrada del usuario de AD

# --- Comprobación de Host de Salto ---
if ($env:COMPUTERNAME -eq "IUSSWRDPCAU02") {
    Write-Error "Error, el script se está ejecutando desde la máquina de salto."
    Read-Host "Presiona Enter para salir..."
    exit 1
}

# --- Configuración Inicial de Usuario e Inicialización de Logging ---
try {
    $GlobalAdUser = Read-Host "Introduce tu usuario de AD (sin @JUSTICIA)"
    if ([string]::IsNullOrWhiteSpace($GlobalAdUser)) {
        Write-Error "El usuario de AD no puede estar vacío."
        Read-Host "Presiona Enter para salir..."
        exit 1
    }

    # $GlobalUserProfileName and $GlobalCurrentHostname are already set from $env
    # Establecer la ruta completa de LOG_FILE ahora que se conoce adUser
    $timestampLogName = Get-Date -Format "yyyyMMdd_HHmmss"
    $GlobalLogFile = Join-Path $GlobalLogDir "$($GlobalAdUser)_$($GlobalCurrentHostname)_$($timestampLogName).log"

    # Mensajes iniciales de log
    Write-Log -Message "Script CAUJUS_dev.ps1 iniciado."
    Write-Log -Message "Usuario: $($GlobalUserProfileName), Usuario AD: $($GlobalAdUser), Máquina: $($GlobalCurrentHostname). Registrando en: $($GlobalLogFile)"

    # Intento de pre-crear el directorio de log aquí explícitamente si Write-Log no lo maneja lo suficientemente pronto para el primer mensaje
    if (-not (Test-Path $GlobalLogDir -PathType Container)) {
        New-Item -Path $GlobalLogDir -ItemType Directory -Force | Out-Null
        Write-Log -Message "Directorio de log creado: $($GlobalLogDir)"
    } else {
        Write-Log -Message "El directorio de log ya existe: $($GlobalLogDir)"
    }

    Write-Log -Message "Intentando instalación inicial de ISL MSI para $GlobalAdUser@JUSTICIA."
    # La ruta al MSI ($ConfigIslMsiPath) debe estar entrecomillada para msiexec
    $islCommand = "msiexec /i \`"$($ConfigIslMsiPath)\`" /qn"
    Write-Log -Message "Preparando comando de instalación ISL: $islCommand"

    $islInstallResult = Invoke-ElevatedCommand -CommandToRun $islCommand

    if ($islInstallResult -eq 0) {
        Write-Log -Message "La instalación inicial de ISL MSI mediante Invoke-ElevatedCommand tuvo éxito."
    } else {
        Write-Log -Message "La instalación inicial de ISL MSI mediante Invoke-ElevatedCommand falló o se ejecutó con errores. Código de salida: $islInstallResult" -Level "ERROR"
    }

}
catch {
    Write-Error "Error durante la configuración inicial: $($_.Exception.Message)"
    # Intentar registrar el error si es posible
    if (-not [string]::IsNullOrWhiteSpace($GlobalLogFile))) {
        Write-Log -Message "ERROR CRÍTICO durante la configuración inicial: $($_.Exception.Message)" -Level "ERROR"
    }
    Read-Host "Presiona Enter para salir..."
    exit 1
}
# --- Fin de Configuración Inicial de Usuario e Inicialización de Logging ---

# --- Funcionalidad de Logging ---
function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARN", "ERROR", "RUNAS")]
        [string]$Level = "INFO"
    )

    # Asegurar que el Directorio de Log Exista
    if (-not (Test-Path $GlobalLogDir -PathType Container)) {
        try {
            New-Item -Path $GlobalLogDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Warning "Falló la creación del directorio de log: $($GlobalLogDir). Error: $($_.Exception.Message)"
            # Podría ser necesario un manejo de errores críticos o alternativo si el logging es absolutamente esencial antes de este punto
            return
        }
    }

    # Asegurar que LOG_FILE esté inicializado (se establecerá completamente después de la entrada del Usuario AD)
    if ([string]::IsNullOrWhiteSpace($GlobalLogFile)) {
        # Esta condición es una salvaguarda. LOG_FILE debería estar establecido antes del primer mensaje de log importante.
        # Por ahora, no registraremos si LOG_FILE no está configurado, o podríamos definir un log temporal pre-inicialización.
        # Sin embargo, el plan es establecer LOG_FILE después de obtener $GlobalAdUser.
        Write-Warning "LOG_FILE no está configurado. Mensaje no registrado: $Message"
        return
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $Level - $Message"

    try {
        Add-Content -Path $GlobalLogFile -Value $logEntry -ErrorAction Stop
    }
    catch {
        Write-Warning "Falló la escritura al archivo de log: $($GlobalLogFile). Error: $($_.Exception.Message)"
    }
}
# --- Fin de Funcionalidad de Logging ---

# --- Función Auxiliar para Ejecutar Comandos con Elevación ---
function Invoke-ElevatedCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CommandToRun,

        [Parameter(Mandatory = $false)]
        [switch]$NoNewWindow = $true # Por defecto a true para comandos cmd /c
    )

    if ([string]::IsNullOrWhiteSpace($GlobalAdUser)) {
        Write-Log -Message "Invoke-ElevatedCommand: adUser no está configurado. No se puede continuar." -Level "ERROR"
        # Opcionalmente, volver a solicitar o salir
        # Read-Host "Error crítico: Usuario AD no configurado. Presiona Enter para salir."
        # exit 1 # O manejarlo de forma más elegante dependiendo de dónde se llame
        return -1 # Indicar fallo
    }

    # Determinar el dominio del equipo
    try {
        $computerDomain = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop).Domain
    }
    catch {
        $computerDomain = $null # Manejar casos donde el dominio no está disponible o la consulta WMI falla
    }

    # Establecer fullUser basado en el dominio
    if ($computerDomain -ne $null -and $computerDomain.ToUpper() -eq 'JUSTICIA') {
        $fullUser = "$($GlobalAdUser)@JUSTICIA"
    }
    else {
        $fullUser = $GlobalAdUser # Usar cuenta local si no está en el dominio JUSTICIA o el dominio es nulo
    }

    # Asegurarse de que el comando entre comillas esté correctamente escapado si contiene comillas.
    # Para comandos simples pasados como cadenas, la incrustación directa suele estar bien.
    # Los comandos complejos pueden necesitar un manejo cuidadoso de las comillas anidadas.
    $runasArgs = "/user:$fullUser /savecred `"$CommandToRun`""

    Write-Log -Message "Intentando ejecutar con elevación: $CommandToRun (Usuario: $fullUser)" -Level "RUNAS"

    try {
        $process = Start-Process runas.exe -ArgumentList $runasArgs -Wait -PassThru -ErrorAction Stop -WindowStyle Hidden # Usar Hidden para comandos de consola
        if ($NoNewWindow -eq $false) { # Si se espera/permite una nueva ventana (ej. para aplicaciones GUI)
             $process = Start-Process runas.exe -ArgumentList $runasArgs -Wait -PassThru -ErrorAction Stop
        }


        Write-Log -Message "Comando elevado ejecutado. Comando: `"$CommandToRun`". Código de Salida: $($process.ExitCode)" -Level "INFO"
        return $process.ExitCode
    }
    catch {
        Write-Log -Message "Falló el inicio del proceso elevado para el comando: `"$CommandToRun`". Error: $($_.Exception.Message)" -Level "ERROR"
        # Error específico de acceso denegado si runas falla debido a credenciales incorrectas (aunque /savecred complica esto)
        if ($_.Exception.NativeErrorCode -eq 5) { # Acceso denegado
             Write-Log -Message "Error de Acceso Denegado al intentar ejecutar como. Asegúrate de que las credenciales para $fullUser estén guardadas y sean válidas." -Level "ERROR"
        }
        return -1 # Indicar fallo (o un código de error específico)
    }
}
# --- Fin de Función Auxiliar ---

# --- Función Auxiliar para Ejecutar Bloques de Script PowerShell Elevados ---
function Invoke-ElevatedPowerShellCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ScriptBlockContent,

        [Parameter(Mandatory = $false)]
        [switch]$NoNewWindow = $true # Por defecto a true, similar a Invoke-ElevatedCommand para comandos de consola
    )

    Write-Log -Message "Preparando para ejecutar contenido de script PowerShell elevado." -Level "INFO"

    try {
        $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ScriptBlockContent))
        $commandForPowerShell = "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"

        Write-Log -Message "Comando PowerShell codificado: $commandForPowerShell" # Registrar el comando para depuración si es necesario

        $exitCode = Invoke-ElevatedCommand -CommandToRun $commandForPowerShell -NoNewWindow:$NoNewWindow
        return $exitCode
    }
    catch {
        Write-Log -Message "Error preparando o invocando comando PowerShell elevado: $($_.Exception.Message)" -Level "ERROR"
        return -1 # Indicar fallo
    }
}
# --- Fin de Función Auxiliar para PowerShell Elevado ---

# --- Funcionalidad de Carga de Log ---
function Upload-LogFile {
    [CmdletBinding()]
    param () # No se necesitan parámetros, usa variables globales

    if ([string]::IsNullOrWhiteSpace($GlobalLogFile) -or (-not (Test-Path $GlobalLogFile -PathType Leaf))) {
        Write-Log -Message "Upload-LogFile: La ruta del archivo de log no está configurada o el archivo no existe: $($GlobalLogFile)" -Level "WARN"
        return $false
    }

    if ([string]::IsNullOrWhiteSpace($ConfigRemoteLogDir)) {
        Write-Log -Message "Upload-LogFile: El directorio de log remoto (ConfigRemoteLogDir) no está configurado." -Level "ERROR"
        return $false
    }

    Write-Log -Message "Preparando para cargar el archivo de log $($GlobalLogFile) al recurso compartido de red."

    # Extraer nombre de archivo de la ruta completa de $GlobalLogFile
    $logFileName = Split-Path -Path $GlobalLogFile -Leaf
    $finalLogPathOnShare = Join-Path $ConfigRemoteLogDir $logFileName

    # Asegurar que el directorio de log remoto exista usando comando PowerShell mediante Invoke-ElevatedPowerShellCommand
    # Usando -LiteralPath para Test-Path y New-Item para manejar posibles caracteres especiales en $ConfigRemoteLogDir
    $psMkdirCommand = "if (-not (Test-Path -LiteralPath \`"$ConfigRemoteLogDir\`" -PathType Container)) { New-Item -Path \`"$ConfigRemoteLogDir\`" -ItemType Directory -Force -ErrorAction Stop | Out-Null }"
    Write-Log -Message "Asegurando que el directorio de log remoto exista con bloque de script PowerShell: $psMkdirCommand"
    $mkdirResult = Invoke-ElevatedPowerShellCommand -ScriptBlockContent $psMkdirCommand # -NoNewWindow $true es por defecto

    if ($mkdirResult -ne 0) {
        Write-Log -Message "Falló la creación o verificación del directorio de log remoto usando Invoke-ElevatedPowerShellCommand: $ConfigRemoteLogDir. Código de Salida de ejecución PowerShell: $mkdirResult. Carga abortada." -Level "ERROR"
        return $false
    }
    Write-Log -Message "Directorio de log remoto confirmado o creado: $ConfigRemoteLogDir"

    # Copiar el archivo de log usando PowerShell Copy-Item mediante Invoke-ElevatedPowerShellCommand
    # Usando -LiteralPath para origen y -Destination para ruta de destino
    $psCopyCommand = "Copy-Item -LiteralPath \`"$($GlobalLogFile)\`" -Destination \`"$finalLogPathOnShare\`" -Force -ErrorAction Stop"
    Write-Log -Message "Intentando copiar archivo de log con bloque de script PowerShell: $psCopyCommand"
    $copyResult = Invoke-ElevatedPowerShellCommand -ScriptBlockContent $psCopyCommand # -NoNewWindow $true es por defecto

    if ($copyResult -eq 0) {
        Write-Log -Message "Intento de carga de archivo de log con Invoke-ElevatedPowerShellCommand exitoso a $finalLogPathOnShare."
        return $true
    } else {
        Write-Log -Message "Carga de archivo de log con Invoke-ElevatedPowerShellCommand fallida. Código de Salida de ejecución PowerShell: $copyResult. Origen: $($GlobalLogFile), Destino: $finalLogPathOnShare" -Level "ERROR"
        return $false
    }
}
# --- Fin de Funcionalidad de Carga de Log ---

# --- Funcionalidad de Auto-eliminación ---
function Invoke-SelfDelete {
    [CmdletBinding()]
    param ()

    Write-Log -Message "Iniciando secuencia de auto-eliminación."

    # Cargar el archivo de log antes de eliminar el script
    Write-Log -Message "Intentando cargar el archivo de log antes de la auto-eliminación."
    $uploadSuccess = Upload-LogFile
    if ($uploadSuccess) {
        Write-Log -Message "Archivo de log cargado exitosamente antes de la auto-eliminación."
    } else {
        Write-Log -Message "La carga del archivo de log falló o se omitió antes de la auto-eliminación. Comprueba los logs anteriores." -Level "WARN"
    }

    $currentScriptPath = $MyInvocation.MyCommand.Path
    Write-Log -Message "Ruta del script a eliminar: $currentScriptPath"

    try {
        # Registrar este mensaje justo antes de la eliminación real
        Write-Log -Message "Intentando eliminar el archivo de script ahora: $currentScriptPath"

        # Breve pausa para asegurar que el log se escriba antes de que el archivo desaparezca
        Start-Sleep -Milliseconds 200

        Remove-Item -Path $currentScriptPath -Force -ErrorAction Stop

        # Este mensaje de abajo no se registrará en el archivo eliminado,
        # pero está aquí para completar lo que la función intenta hacer.
        # Si hubiera un logging central/externo, podría ir allí.
        # Write-Log -Message "El archivo de script ha sido eliminado." # Esto no llegará a su propio log

        Write-Host "El script ha sido eliminado y ahora saldrá."
        Start-Sleep -Seconds 1 # Permitir al usuario ver el mensaje
        Exit 0 # Salir de la ejecución del script
    }
    catch {
        # Esto tampoco llegará probablemente al archivo de log si la eliminación fue parcial o la ruta ahora es incorrecta
        Write-Log -Message "Error durante la auto-eliminación: $($_.Exception.Message). El script aún podría existir en $currentScriptPath" -Level "ERROR"
        Write-Host "Error al intentar auto-eliminarse. El script aún podría existir."
        Read-Host "Presiona Enter para salir..."
        Exit 1 # Salir con un código de error
    }
}
# --- Fin de Funcionalidad de Auto-eliminación ---

# --- Funciones Auxiliares de Batery_test ---
function DetenerNavegadoresComunes {
    Write-Log -Message "BT: Terminando procesos comunes de navegadores."
    $browsers = "chrome", "iexplore", "msedge", "firefox" # Firefox añadido
    foreach ($browser in $browsers) {
        Stop-Process -Name $browser -Force -ErrorAction SilentlyContinue
        if ($?) { Write-Log -Message "BT: Proceso $browser detenido o no se estaba ejecutando." } # $? podría ser true incluso si el proceso no se encuentra con SilentlyContinue
    }
}

function LimpiarCachesSistemaUsuario {
    Write-Log -Message "BT: Limpiando cachés del sistema y del usuario."

    Write-Log -Message "BT: Limpiando caché DNS."
    Clear-DnsClientCache
    Write-Log -Message "BT: Caché DNS limpiada."

    $clearTracksCommands = @(
        "RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 16", # Contraseñas
        "RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8",  # Historial
        "RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 2",  # Cookies
        "RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 1"   # Archivos temporales de Internet
    )
    foreach ($command in $clearTracksCommands) {
        Write-Log -Message "BT: Ejecutando limpieza de caché: $command"
        try {
            # Dividiendo comando y argumentos para Start-Process
            $executable = $command.Split(' ',2)[0]
            $arguments = $command.Split(' ',2)[1]
            Start-Process -FilePath $executable -ArgumentList $arguments -Wait -NoNewWindow -ErrorAction Stop
            Write-Log -Message "BT: Ejecutado $command con éxito"
        } catch {
            Write-Log -Message "BT: Falló la ejecución de $command. Error: $($_.Exception.Message)" -Level "WARN"
        }
    }

    $chromeCachePath = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data\Default\Cache"
    if (Test-Path $chromeCachePath) {
        Write-Log -Message "BT: Limpiando caché de Chrome en $chromeCachePath"
        # Asegurarse de que la ruta para Remove-Item esté correctamente entrecomillada si pudiera contener espacios, aunque $chromeCachePath típicamente no los tiene.
        Remove-Item -Path "$($chromeCachePath)\*" -Recurse -Force -ErrorAction SilentlyContinue
        # Con ErrorAction SilentlyContinue, $? debería ser $true si el comando no tuvo errores fatales para PowerShell en sí.
        # No se puede garantizar que todos los archivos hayan sido eliminados sin una verificación explícita posterior.
        Write-Log -Message "BT: Intento de limpieza de caché de Chrome en $chromeCachePath completado (ErrorAction: SilentlyContinue)."
    } else {
        Write-Log -Message "BT: Ruta de caché de Chrome no encontrada: $chromeCachePath" -Level "WARN"
    }
}

function AplicarAjustesRegistroEfectosVisuales {
    Write-Log -Message "BT: Aplicando ajustes de registro para efectos visuales."
    # Usando rutas HKCU directamente. Estas se aplican al contexto de usuario bajo el cual Invoke-ElevatedCommand ejecuta el comando REG.
    # Si $GlobalAdUser es diferente del usuario actual, estos se aplican al HKCU de $GlobalAdUser.
    $regTweaks = @{
        "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" = @{ "MinAnimate" = @{ Value = "0"; Type = "REG_SZ" } }
        "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{ "TaskbarAnimations" = @{ Value = 0; Type = "REG_DWORD" } }
        "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" = @{
            "VisualFXSetting" = @{ Value = 2; Type = "REG_DWORD" };
            "ComboBoxAnimation" = @{ Value = 0; Type = "REG_DWORD" };
            "CursorShadow" = @{ Value = 0; Type = "REG_DWORD" };
            "DropShadow" = @{ Value = 0; Type = "REG_DWORD" };
            "ListBoxSmoothScrolling" = @{ Value = 0; Type = "REG_DWORD" };
            "MenuAnimation" = @{ Value = 0; Type = "REG_DWORD" };
            "SelectionFade" = @{ Value = 0; Type = "REG_DWORD" };
            "TooltipAnimation" = @{ Value = 0; Type = "REG_DWORD" };
            "Fade" = @{ Value = 0; Type = "REG_DWORD" } # Asumiendo que esto también era para VisualEffects
        }
    }

    foreach ($path in $regTweaks.Keys) {
        $values = $regTweaks[$path]
        foreach ($name in $values.Keys) {
            $item = $values[$name]
            $valueData = $item.Value
            $valueType = $item.Type

            # La ruta para REG ADD necesita ser no escapada (sin prefijo 'HKEY_CURRENT_USER:' de PS)
            $regPathForCommand = $path.Replace("HKEY_CURRENT_USER", "HKCU") # O usar HKEY_CURRENT_USER completo
                                    .Replace("HKEY_LOCAL_MACHINE", "HKLM") # Si alguna vez es necesario

            $command = "REG ADD `"$regPathForCommand`" /v `"$name`" /t $valueType /d `"$valueData`" /f"
            Write-Log -Message "BT: Aplicando ajuste de registro: $command"
            $result = Invoke-ElevatedCommand -CommandToRun $command
            if ($result -ne 0) {
                Write-Log -Message "BT: Falló la aplicación del ajuste de registro para $name en $regPathForCommand. Código de salida: $result" -Level "WARN"
            }
        }
    }
    Write-Log -Message "BT: Proceso de aplicación de ajustes de registro para efectos visuales finalizado."
}

function RealizarTareasMantenimientoSistema {
    Write-Log -Message "BT: Realizando tareas de mantenimiento del sistema."

    Write-Log -Message "BT: Ejecutando gpupdate /force."
    $gpResult = Invoke-ElevatedCommand -CommandToRun "gpupdate /force"
    Write-Log -Message "BT: gpupdate /force completado. Código de salida: $gpResult"

    Write-Log -Message "BT: Asegurando que ISL esté instalado (re-ejecutando instalador)."
    $islCommand = "msiexec /i \`"$($ConfigIslMsiPath)\`" /qn" # $ConfigIslMsiPath debería estar correctamente definido globalmente
    $islResult = Invoke-ElevatedCommand -CommandToRun $islCommand
    Write-Log -Message "BT: Instalador ISL MSI ejecutado. Código de salida: $islResult"

    # Rutas de todo el sistema para limpieza
    Write-Log -Message "BT: Limpiando rutas de todo el sistema."
    $pathsToCleanSystemDrive = @(
        "%windir%\*.bak",
        "%windir%\SoftwareDistribution\Download\*.*",
        "%SystemDrive%\*.tmp",
        "%SystemDrive%\*._mp",
        "%SystemDrive%\*.gid",
        "%SystemDrive%\*.chk",
        "%SystemDrive%\*.old"
    )

    foreach ($pathPattern in $pathsToCleanSystemDrive) {
        $psPath = $pathPattern.Replace("%windir%", '$env:windir') `
                               .Replace("%SystemDrive%", '$env:SystemDrive') `
                               .Replace("%TEMP%", '$env:TEMP') `
                               .Replace("%LOCALAPPDATA%", '$env:LOCALAPPDATA') `
                               .Replace("%APPDATA%", '$env:APPDATA') `
                               .Replace("*.*", "*") `
                               .Replace("`"", "") # Eliminar comillas externas del patrón original si quedara alguna

        $psCommand = "Remove-Item -Path '${psPath}' -Recurse -Force -ErrorAction Stop"
        Write-Log -Message "BT: Limpiando archivos con bloque de script PowerShell: $psCommand"
        Invoke-ElevatedPowerShellCommand -ScriptBlockContent $psCommand
    }

    # Rutas específicas del usuario para limpieza
    Write-Log -Message "BT: Limpiando rutas específicas del usuario (Nota: el contexto es para el Usuario AD: $($GlobalAdUser))." -Level "WARN"
    $userSpecificPathsForElevatedDel = @(
        "%TEMP%\*.*",
        "%LOCALAPPDATA%\Microsoft\Windows\Temporary Internet Files\*.*",
        "%LOCALAPPDATA%\Microsoft\Windows\INetCache\*.*",
        "%LOCALAPPDATA%\Microsoft\Windows\INetCookies\*.*",
        "%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\*.*",
        "%LOCALAPPDATA%\CrashDumps\*.*",
        "%APPDATA%\Microsoft\Windows\cookies\*.*"
    )

    foreach ($pathPattern in $userSpecificPathsForElevatedDel) {
        $psPath = $pathPattern.Replace("%windir%", '$env:windir') `
                               .Replace("%SystemDrive%", '$env:SystemDrive') `
                               .Replace("%TEMP%", '$env:TEMP') `
                               .Replace("%LOCALAPPDATA%", '$env:LOCALAPPDATA') `
                               .Replace("%APPDATA%", '$env:APPDATA') `
                               .Replace("*.*", "*") `
                               .Replace("`"", "")

        # Para rutas específicas del usuario, es bueno asegurarse de que el directorio padre exista antes de intentar la eliminación,
        # aunque Remove-Item con -Force y SilentlyContinue maneja rutas inexistentes elegantemente.
        # El IF EXIST original era para cmd.exe; Remove-Item maneja esto inherentemente.
        $psCommand = "Remove-Item -Path '${psPath}' -Recurse -Force -ErrorAction Stop"
        Write-Log -Message "BT: Limpiando archivos de usuario con bloque de script PowerShell: $psCommand"
        Invoke-ElevatedPowerShellCommand -ScriptBlockContent $psCommand
    }

    # Recreando carpetas
    Write-Log -Message "BT: Recreando carpetas especificadas (Nota: el contexto es para el Usuario AD: $($GlobalAdUser) si se usan variables de entorno como %windir% directamente)."
    $foldersToRecreate = @(
        "%windir%\Temp"
        # "%USERPROFILE%\Local Settings\Temp" # Esto es efectivamente $env:TEMP, manejado por la limpieza específica del usuario si el patrón coincide
    )

    foreach ($folderPathPattern in $foldersToRecreate) {
        $psPath = $folderPathPattern.Replace("%windir%", '$env:windir') `
                                    .Replace("%SystemDrive%", '$env:SystemDrive') `
                                    .Replace("%TEMP%", '$env:TEMP') `
                                    .Replace("%LOCALAPPDATA%", '$env:LOCALAPPDATA') `
                                    .Replace("%APPDATA%", '$env:APPDATA') `
                                    .Replace("`"", "")

        $psCommand = "Remove-Item -Path '${psPath}' -Recurse -Force -ErrorAction Stop; New-Item -Path '${psPath}' -ItemType Directory -Force -ErrorAction Stop"
        Write-Log -Message "BT: Recreando carpeta con bloque de script PowerShell: $psCommand"
        Invoke-ElevatedPowerShellCommand -ScriptBlockContent $psCommand
    }
    Write-Log -Message "BT: Tareas de mantenimiento del sistema finalizadas."
}
# --- Fin de Funciones Auxiliares de Batery_test ---

# --- Función Principal de Batery_test ---
function InvocarBateriaPruebas {
    Write-Log -Message "Acción: Iniciando Batería de Pruebas." # Updated message

    DetenerNavegadoresComunes
    LimpiarCachesSistemaUsuario
    AplicarAjustesRegistroEfectosVisuales
    RealizarTareasMantenimientoSistema

    Write-Log -Message "INFO - Acción: Solicitando reinicio en Batería de Pruebas." # Updated message
    Write-Host "`nBatería de pruebas completada." # Añadido salto de línea para mejor espaciado

    $validResponse = $false
    $restartChoice = ""
    while (-not $validResponse) {
        $restartChoice = Read-Host "Reiniciar equipo ahora? (s/n)"
        if ($restartChoice.ToLower() -match '^[sn]$') { # .ToLower() para insensibilidad a mayúsculas/minúsculas
            $validResponse = $true
        } else {
            Write-Warning "Respuesta no válida. Introduce 's' para sí o 'n' para no."
        }
    }

    if ($restartChoice.ToLower() -eq 's') { # Asegurar insensibilidad a mayúsculas/minúsculas por seguridad
        Write-Log -Message "Usuario eligió reiniciar."

        Write-Log -Message "Intentando cargar archivo de log antes del reinicio del sistema."
        $uploadSuccess = Upload-LogFile
        if ($uploadSuccess) {
            Write-Log -Message "Archivo de log cargado exitosamente antes del reinicio."
        } else {
            Write-Log -Message "La carga del archivo de log falló o se omitió antes del reinicio. Comprueba los logs anteriores." -Level "WARN"
        }

        Write-Log -Message "Iniciando reinicio del equipo AHORA."
        Restart-Computer -Force

        # --- Auto-eliminación de mejor esfuerzo después del comando de reinicio ---
        # Las siguientes líneas son un intento de mejor esfuerzo ya que Restart-Computer podría terminar la ejecución del script abruptamente.
        Write-Log -Message "Intentando auto-eliminación del script post-comando de reinicio (mejor esfuerzo)."
        $currentScriptPathForDelete = $MyInvocation.MyCommand.Path # Usar un nombre de variable diferente para evitar conflictos si $currentScriptPath se usa en otro lugar
        try {
            # Breve pausa, puede permitir que los logs se vacíen o que el reinicio se inicialice completamente en segundo plano.
            Start-Sleep -Milliseconds 250
            if (Test-Path $currentScriptPathForDelete -PathType Leaf) {
                Remove-Item -Path $currentScriptPathForDelete -Force -ErrorAction SilentlyContinue
                # Registrar este intento, pero podría no escribirse si el reinicio es demasiado rápido.
                # Considerar que esta entrada de log es para un escenario donde el script *podría* continuar por un momento.
                Add-Content -Path $GlobalLogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - INFO - Auto-eliminación mejor esfuerzo: Comando Remove-Item emitido para $currentScriptPathForDelete." -ErrorAction SilentlyContinue
            }
        }
        catch {
            # Este bloque catch y su log también son de mejor esfuerzo.
            Add-Content -Path $GlobalLogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - WARN - Auto-eliminación mejor esfuerzo: Error intentando eliminar script $currentScriptPathForDelete. Error: $($_.Exception.Message)" -ErrorAction SilentlyContinue
        }
        # La ejecución del script será asumida por el proceso de reinicio. No se necesita Exit explícito aquí.
    } else {
        Write-Log -Message "Usuario eligió no reiniciar. Cargando log y auto-eliminando script."
        Invoke-SelfDelete # Esta función maneja la carga de logs, la eliminación del script y luego sale.
    }
    # La ejecución del script se detiene efectivamente aquí debido a Invoke-SelfDelete o Restart-Computer (en el caso 's').
}
# --- Fin de la Función Principal de Batery_test ---

# --- Función Cambiar Contraseña Correo ---
function AbrirUrlCambiarContraseña {
    Write-Log -Message "Acción: Iniciando AbrirUrlCambiarContraseña. Abriendo URL: $($ConfigUrlMiCuentaJunta)"

    try {
        Start-Process "chrome.exe" -ArgumentList $ConfigUrlMiCuentaJunta -ErrorAction Stop
        Write-Log -Message "Chrome iniciado con éxito con URL: $($ConfigUrlMiCuentaJunta)"
    }
    catch {
        Write-Log -Message "Falló el inicio de Chrome con URL: $($ConfigUrlMiCuentaJunta). Error: $($_.Exception.Message)" -Level "ERROR"
        Write-Warning "No se pudo abrir Chrome. Verifica que esté instalado y accesible."
        # Decidir si aún debemos auto-eliminarnos o volver al menú
        Read-Host "Presiona Enter para continuar..."
        return # Volver al menú principal si Chrome no se inicia
    }

    # El script original se auto-elimina después de esta acción
    Write-Log -Message "URL abierta. El script ahora se auto-eliminará según la lógica original."
    InvocarAutoeliminacion # Esto maneja la carga de logs, eliminación del script y salida
}
# --- Fin Función Cambiar Contraseña Correo ---

# --- Función Reiniciar Cola Impresión ---
function ReiniciarServicioColaImpresion {
    Write-Log -Message "Acción: Iniciando ReiniciarServicioColaImpresion." # Updated message

    # El comando del script batch es complejo debido al bucle FOR y comandos incrustados.
    # El escapado para la ejecución de cmd /c mediante Invoke-ElevatedCommand necesita cuidado.
    # Original: FOR /F "tokens=3,*" %%a IN ('cscript c:\windows\System32\printing_Admin_Scripts\es-ES\prnmngr.vbs -l ^| FINDSTR "Nombre de impresora"') DO cscript c:\windows\System32\printing_Admin_Scripts\es-ES\prnqctl.vbs -m -p "%%b"
    # Traducción de PowerShell para la cadena de comando:
    # - %%a se convierte en %a, %%b se convierte en %b dentro de la cadena cmd /c
    # - Comillas simples internas para la cláusula IN de FOR
    # - Comillas escapadas para FINDSTR y para el parámetro -p
    # - El carácter de tubería ^| se convierte en solo | dentro de la cadena cmd /c, pero podría necesitar escapado si PowerShell lo analiza primero.
    #   Es más seguro pasar todo como una cadena literal a cmd /c.

    $vbScriptPath = "c:\windows\System32\printing_Admin_Scripts\es-ES" # Ruta estándar
    $prnmngrCmd = "cscript.exe `"$vbScriptPath\prnmngr.vbs`" -l"
    $findstrCmd = "FINDSTR `"/C:Nombre de impresora`"" # Usando /C: para cadena de búsqueda literal
    $prnqctlBaseCmd = "cscript.exe `"$vbScriptPath\prnqctl.vbs`" -m -p"

    # Construyendo la cadena de comando del bucle FOR para cmd.exe:
    # Nota: %%a y %%b son para archivos batch. En una línea de comando CMD directa, son %a y %b.
    # `cmd /c` interpretará %a y %b correctamente.
    $commandToRun = "FOR /F `"tokens=3,*`" %a IN ('$prnmngrCmd ^| $findstrCmd') DO $prnqctlBaseCmd `"%b`""
    # Comando completo para cmd /c
    $fullCmdCommand = "cmd /c $commandToRun"

    Write-Log -Message "Intentando reiniciar colas de impresión con comando: $fullCmdCommand" -Level "RUNAS"

    $result = Invoke-ElevatedCommand -CommandToRun $fullCmdCommand -NoNewWindow $true # Asegurar NoNewWindow

    if ($result -eq 0) {
        Write-Log -Message "Comando de reinicio de cola de impresión ejecutado con éxito (Código de Salida: $result)."
        Write-Host "Comando para reiniciar las colas de impresión ejecutado."
    } else {
        Write-Log -Message "Comando de reinicio de cola de impresión falló o se ejecutó con errores (Código de Salida: $result)." -Level "ERROR"
        Write-Warning "El comando para reiniciar las colas de impresión pudo haber fallado (Código de salida: $result)."
    }

    # El script original se auto-elimina después de esta acción
    Write-Log -Message "Acción de reinicio de cola de impresión finalizada. El script ahora se auto-eliminará."
    # Dar un momento al usuario para ver cualquier mensaje del comando si no fue completamente silencioso.
    Read-Host "Presiona Enter para continuar con la salida del script..."
    InvocarAutoeliminacion # Esto maneja la carga de logs, eliminación del script y salida
}
# --- Fin Función Reiniciar Cola Impresión ---

# --- Función Administrador de Dispositivos ---
function MostrarAdministradorDispositivos {
    Write-Log -Message "Acción: Iniciando MostrarAdministradorDispositivos. Abriendo Administrador de Dispositivos." # Updated message

    # Esto corresponde a la línea 214 del script batch original:
    # CALL :ExecuteWithRunas "RunDll32.exe devmgr.dll DeviceManager_Execute"
    $commandToRun = "RunDll32.exe devmgr.dll DeviceManager_Execute"

    Write-Log -Message "Intentando abrir Administrador de Dispositivos con comando: $commandToRun" -Level "RUNAS"
    $result = Invoke-ElevatedCommand -CommandToRun $commandToRun -NoNewWindow $false # Asegurar que la GUI sea visible

    if ($result -eq 0) {
        Write-Log -Message "Comando de inicio del Administrador de Dispositivos ejecutado con éxito (Código de Salida: $result)."
        Write-Host "Device Manager debería haberse iniciado."
    } else {
        Write-Log -Message "Comando de inicio del Administrador de Dispositivos falló o se ejecutó con errores (Código de Salida: $result)." -Level "ERROR"
        Write-Warning "El comando para iniciar el Administrador de Dispositivos pudo haber fallado (Código de salida: $result)."
    }

    # A diferencia de otras opciones, el script original vuelve al menú principal aquí, no se auto-elimina.
    Write-Log -Message "Acción del Administrador de Dispositivos finalizada. Volviendo al menú principal."
    Read-Host "Presiona Enter para volver al menú principal..."
    # MostrarMenuPrincipal será llamado por el bucle principal después de que esta función regrese
}
# --- Fin Función Administrador de Dispositivos ---

# --- Menú Gestionar Certificados Digitales ---
function MostrarMenuCertificadosDigitales {
    Write-Log -Message "Acción: Navegado al Menú de Certificados Digitales."
    Clear-Host
    Write-Host "------------------------------------------"
    Write-Host "             CERTIFICADOS DIGITALES"
    Write-Host "------------------------------------------"
    Write-Host "1. Abrir FNMT: Solicitar Certificado"
    Write-Host "2. Abrir FNMT: Renovar Certificado"
    Write-Host "3. Abrir FNMT: Descargar Certificado"
    Write-Host "4. Abrir Administrador de Certificados (certmgr.msc)"
    Write-Host "M. Volver al Menú Principal"
    Write-Host ""

    $certChoice = Read-Host "Escoge una opcion"
    Write-Log -Message "Menú Certificados Digitales: Usuario seleccionó la opción '$certChoice'."

    switch ($certChoice.ToLower()) { # Usar .ToLower() para insensibilidad a mayúsculas/minúsculas
        '1' {
            Write-Log -Message "Intentando abrir URL FNMT Solicitar: $ConfigUrlFnmtSolicitar"
            try {
                Start-Process "chrome.exe" -ArgumentList $ConfigUrlFnmtSolicitar -ErrorAction Stop
                Write-Log -Message "Chrome iniciado con éxito con URL FNMT Solicitar."
            }
            catch {
                Write-Log -Message "Falló el inicio de Chrome para URL FNMT Solicitar. Error: $($_.Exception.Message)" -Level "ERROR"
                Write-Warning "No se pudo abrir Chrome para FNMT Solicitar. Verifica que esté instalado."
            }
            Read-Host "Presiona Enter para continuar..."
            MostrarMenuCertificadosDigitales # Volver al bucle
        }
        '2' {
            Write-Log -Message "Intentando abrir URL FNMT Renovar: $ConfigUrlFnmtRenovar"
            try {
                Start-Process "chrome.exe" -ArgumentList $ConfigUrlFnmtRenovar -ErrorAction Stop
                Write-Log -Message "Chrome iniciado con éxito con URL FNMT Renovar."
            }
            catch {
                Write-Log -Message "Falló el inicio de Chrome para URL FNMT Renovar. Error: $($_.Exception.Message)" -Level "ERROR"
                Write-Warning "No se pudo abrir Chrome para FNMT Renovar. Verifica que esté instalado."
            }
            Read-Host "Presiona Enter para continuar..."
            MostrarMenuCertificadosDigitales # Volver al bucle
        }
        '3' {
            Write-Log -Message "Intentando abrir URL FNMT Descargar: $ConfigUrlFnmtDescargar"
            try {
                Start-Process "chrome.exe" -ArgumentList $ConfigUrlFnmtDescargar -ErrorAction Stop
                Write-Log -Message "Chrome iniciado con éxito con URL FNMT Descargar."
            }
            catch {
                Write-Log -Message "Falló el inicio de Chrome para URL FNMT Descargar. Error: $($_.Exception.Message)" -Level "ERROR"
                Write-Warning "No se pudo abrir Chrome para FNMT Descargar. Verifica que esté instalado."
            }
            Read-Host "Presiona Enter para continuar..."
            MostrarMenuCertificadosDigitales # Volver al bucle
        }
        '4' {
            Write-Log -Message "Intentando abrir Administrador de Certificados (certmgr.msc)."
            try {
                Start-Process "certmgr.msc" -ErrorAction Stop
                Write-Log -Message "certmgr.msc iniciado con éxito."
            }
            catch {
                Write-Log -Message "Falló el inicio de certmgr.msc. Error: $($_.Exception.Message)" -Level "ERROR"
                Write-Warning "No se pudo abrir el Administrador de Certificados (certmgr.msc)."
            }
            Read-Host "Presiona Enter para continuar..."
            MostrarMenuCertificadosDigitales # Volver al bucle
        }
        'm' {
            Write-Log -Message "Volviendo al Menú Principal desde el Menú de Certificados Digitales."
            return # Esto permitirá que MostrarMenuPrincipal se vuelva a mostrar
        }
        default {
            Write-Log -Message "Opción inválida '$certChoice' seleccionada en Menú Certificados Digitales." -Level "WARN"
            Write-Warning "'$certChoice' opcion no valida, intentalo de nuevo."
            Start-Sleep -Seconds 2
            MostrarMenuCertificadosDigitales # Volver al bucle
        }
    }
}
# --- Fin Menú Gestionar Certificados Digitales ---

# --- Mostrar Información ISL Always On ---
function MostrarInformacionIslAlwaysOn {
    Write-Log -Message "Acción: Navegado a Información ISL Always On."
    Clear-Host
    Write-Host "------------------------------------------"
    Write-Host "                 ISL ALWAYS ON"
    Write-Host "------------------------------------------"
    Write-Host "Configurar ISL Always On (Acceso Remoto Permanente) es una tarea compleja"
    Write-Host "que usualmente requiere paquetes de instalación específicos y configuración detallada."
    Write-Host ""
    Write-Host "Esta funcionalidad está prevista para una futura implementación automatizada."
    Write-Host "Por ahora, la configuración podría necesitar realizarse manualmente."
    Write-Host ""
    Write-Host "- El software de ISL (si está disponible centralmente) podría encontrarse en:"
    Write-Host "  $ConfigSoftwareBasePath"
    Write-Host "- El script intentó una instalación inicial de ISL Light Client desde:"
    Write-Host "  $ConfigIslMsiPath"
    Write-Host "- Asegúrate que ISL Light Client esté instalado y configurado según sea necesario."
    Write-Host ""
    Read-Host "Presiona Enter para volver al menú principal..."
    Write-Log -Message "Usuario volviendo desde Información ISL Always On al Menú Principal."
    # MostrarMenuPrincipal será llamado por el bucle principal después de que esta función regrese
}
# --- Fin Mostrar Información ISL Always On ---

# --- Mostrar Menú Utilidades ---
function MostrarMenuUtilidades {
    Write-Log -Message "Acción: Navegado al Menú de Utilidades."
    Clear-Host
    Write-Host "------------------------------------------"
    Write-Host "                   UTILIDADES"
    Write-Host "------------------------------------------"
    Write-Host "1. Abrir Liberador de espacio en disco (cleanmgr.exe)"
    Write-Host "2. Abrir Información del sistema (msinfo32.exe)"
    Write-Host "3. Abrir Visor de eventos (eventvwr.msc)"
    Write-Host "4. Abrir Administrador de Tareas (taskmgr.exe)"
    Write-Host "M. Volver al Menú Principal"
    Write-Host ""

    $utilChoice = Read-Host "Escoge una opcion"
    Write-Log -Message "Menú Utilidades: Usuario seleccionó la opción '$utilChoice'."

    switch ($utilChoice.ToLower()) { # Usar .ToLower() para insensibilidad a mayúsculas/minúsculas
        '1' {
            Write-Log -Message "Intentando abrir Liberador de espacio en disco (cleanmgr.exe)."
            try {
                Start-Process "cleanmgr.exe" -ErrorAction Stop
                Write-Log -Message "cleanmgr.exe iniciado con éxito."
            }
            catch {
                Write-Log -Message "Falló el inicio de cleanmgr.exe. Error: $($_.Exception.Message)" -Level "ERROR"
                Write-Warning "No se pudo abrir el Liberador de espacio en disco."
            }
            Read-Host "Presiona Enter para continuar..."
            MostrarMenuUtilidades # Volver al bucle
        }
        '2' {
            Write-Log -Message "Intentando abrir Información del sistema (msinfo32.exe)."
            try {
                Start-Process "msinfo32.exe" -ErrorAction Stop
                Write-Log -Message "msinfo32.exe iniciado con éxito."
            }
            catch {
                Write-Log -Message "Falló el inicio de msinfo32.exe. Error: $($_.Exception.Message)" -Level "ERROR"
                Write-Warning "No se pudo abrir Información del sistema."
            }
            Read-Host "Presiona Enter para continuar..."
            MostrarMenuUtilidades # Volver al bucle
        }
        '3' {
            Write-Log -Message "Intentando abrir Visor de eventos (eventvwr.msc)."
            try {
                Start-Process "eventvwr.msc" -ErrorAction Stop
                Write-Log -Message "eventvwr.msc iniciado con éxito."
            }
            catch {
                Write-Log -Message "Falló el inicio de eventvwr.msc. Error: $($_.Exception.Message)" -Level "ERROR"
                Write-Warning "No se pudo abrir el Visor de eventos."
            }
            Read-Host "Presiona Enter para continuar..."
            MostrarMenuUtilidades # Volver al bucle
        }
        '4' {
            Write-Log -Message "Intentando abrir Administrador de Tareas (taskmgr.exe)."
            try {
                Start-Process "taskmgr.exe" -ErrorAction Stop
                Write-Log -Message "taskmgr.exe iniciado con éxito."
            }
            catch {
                Write-Log -Message "Falló el inicio de taskmgr.exe. Error: $($_.Exception.Message)" -Level "ERROR"
                Write-Warning "No se pudo abrir el Administrador de Tareas."
            }
            Read-Host "Presiona Enter para continuar..."
            MostrarMenuUtilidades # Volver al bucle
        }
        'm' {
            Write-Log -Message "Volviendo al Menú Principal desde el Menú de Utilidades."
            return # Esto permitirá que MostrarMenuPrincipal se vuelva a mostrar
        }
        default {
            Write-Log -Message "Opción inválida '$utilChoice' seleccionada en Menú Utilidades." -Level "WARN"
            Write-Warning "'$utilChoice' opcion no valida, intentalo de nuevo."
            Start-Sleep -Seconds 2
            MostrarMenuUtilidades # Volver al bucle
        }
    }
}
# --- Fin Mostrar Menú Utilidades ---

# (Mantener las líneas Write-Host de marcador de posición existentes o eliminarlas a medida que se añaden funciones)
# Para probar la función Write-Log durante el desarrollo:
# $GlobalLogFile = Join-Path $GlobalLogDir "test_initial.log" # Temporal para pruebas directas
# Write-Log -Message "Entrada de log de prueba desde la estructura inicial del script."
# Write-Log -Message "Otra entrada de log de prueba." -Level "WARN"

# --- Menú Principal e Información del Sistema ---
function MostrarMenuPrincipal {
    Clear-Host # Limpia la pantalla, similar a CLS

    # Recopilar información del sistema
    $computerName = $GlobalCurrentHostname # Ya obtenido
    $serialNumber = (Get-CimInstance Win32_BIOS).SerialNumber
    # Intentar obtener la dirección IPv4 primaria de forma más fiable
    $primaryInterface = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | Sort-Object -Property {$_.Name -notlike "Ethernet*"} | Select-Object -First 1
    $ipAddress = "N/A"
    if ($primaryInterface) {
        $ipConfiguration = Get-NetIPConfiguration -InterfaceIndex $primaryInterface.InterfaceIndex
        $ipv4Address = ($ipConfiguration | Select-Object -ExpandProperty IPv4Address | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -ExpandProperty IPAddress -First 1)
        if ($ipv4Address) {
            $ipAddress = $ipv4Address
        }
    }

    $osInfo = Get-CimInstance Win32_OperatingSystem
    $osCaption = $osInfo.Caption
    $osBuildNumber = $osInfo.BuildNumber

    Write-Log -Message "Info Sistema: Usuario: $($GlobalUserProfileName), Usuario AD: $($GlobalAdUser), Equipo: $computerName, SN: $serialNumber, IP: $ipAddress, SO: $osCaption ($osBuildNumber), Versión Script: $ConfigScriptVersion"

    # Mostrar información del sistema y menú
    Write-Host "------------------------------------------"
    Write-Host "                 CAU"
    Write-Host "------------------------------------------"
    Write-Host ""
    Write-Host "Usuario: $($GlobalUserProfileName)"
    Write-Host "Usuario AD utilizado: $($GlobalAdUser)"
    Write-Host "Nombre equipo: $computerName"
    Write-Host "Número de serie: $serialNumber"
    Write-Host "Número de IP: $ipAddress"
    Write-Host "Versión: $osCaption, con la compilación $osBuildNumber"
    Write-Host "Versión Script: $ConfigScriptVersion"
    Write-Host ""
    Write-Host "1. Batería de pruebas"
    Write-Host "2. Cambiar contraseña correo"
    Write-Host "3. Reiniciar cola de impresión"
    Write-Host "4. Administrador de dispositivos (desinstalar drivers)"
    Write-Host "5. Certificado digital"
    Write-Host "6. ISL Always On"
    Write-Host "7. Utilidades"
    Write-Host "X. Salir" # Añadida una opción de Salir
    Write-Host ""

    $choice = Read-Host "Escoge una opcion"

    Write-Log -Message "Menú principal: Usuario seleccionó la opción '$choice'."

    switch ($choice) {
        "1" { InvocarBateriaPruebas }
        "2" { AbrirUrlCambiarContraseña } # Updated function call
        "3" { ReiniciarServicioColaImpresion } # Updated function call
        "4" { MostrarAdministradorDispositivos; MostrarMenuPrincipal } # Updated function calls
        "5" { MostrarMenuCertificadosDigitales; MostrarMenuPrincipal } # Updated function calls
        "6" { MostrarInformacionIslAlwaysOn; MostrarMenuPrincipal } # Updated function calls
        "7" { MostrarMenuUtilidades; MostrarMenuPrincipal } # Updated function calls
        "X" {
            Write-Host "Saliendo del script."
            Write-Log -Message "Usuario seleccionó Salir. Intentando cargar log antes de terminar."
            Upload-LogFile # Intentar cargar logs al salir normalmente
            Write-Log -Message "Script terminando ahora."
            exit 0
        }
        default {
            Write-Host "'$choice' opcion no valida, intentalo de nuevo."
            Start-Sleep -Seconds 2
            MostrarMenuPrincipal # Updated function call
        }
    }
}
# --- Fin Menú Principal e Información del Sistema ---

# --- La ejecución principal del script comienza aquí ---
# (Esta llamada debe estar al final del script, después de todas las definiciones de funciones)
MostrarMenuPrincipal # Updated function call
# --- Fin de la ejecución principal del script ---
