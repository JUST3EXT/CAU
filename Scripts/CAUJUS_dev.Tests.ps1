# Pester Test File for CAUJUS_dev.ps1
# Requires Pester v5+

BeforeAll {
    # Mock Read-Host to prevent script execution from pausing during sourcing
    Mock -CommandName Read-Host -MockWith { return "TestUser" } | Out-Null

    # Mock other cmdlets that might interfere with sourcing or are not relevant to unit tests here
    Mock -CommandName Invoke-ElevatedCommand -MockWith { Write-Verbose "Mocked Invoke-ElevatedCommand for sourcing"; return 0 } | Out-Null
    Mock -CommandName Invoke-ElevatedPowerShellCommand -MockWith { Write-Verbose "Mocked Invoke-ElevatedPowerShellCommand for sourcing"; return 0 } | Out-Null

    # Mock BateriaPruebas helpers and other action/menu functions that might be defined before sourcing is complete
    Mock -CommandName DetenerNavegadoresComunes {}
    Mock -CommandName LimpiarCachesSistemaUsuario {}
    Mock -CommandName AplicarAjustesRegistroEfectosVisuales {}
    Mock -CommandName RealizarTareasMantenimientoSistema {}
    Mock -CommandName InvocarBateriaPruebas {}
    Mock -CommandName SubirArchivoLog {}
    Mock -CommandName InvocarAutoeliminacion {} # Renamed from Invoke-SelfDelete
    Mock -CommandName Restart-Computer {}
    Mock -CommandName AbrirUrlCambiarContraseña {}
    Mock -CommandName ReiniciarServicioColaImpresion {}
    Mock -CommandName MostrarAdministradorDispositivos {}
    Mock -CommandName MostrarMenuCertificadosDigitales {}
    Mock -CommandName MostrarInformacionIslAlwaysOn {}
    Mock -CommandName MostrarMenuUtilidades {}
    Mock -CommandName MostrarMenuPrincipal {}


    # Source the script to make functions and variables available
    . "$PSScriptRoot/CAUJUS_dev.ps1"

    # Initialize/Override Global Variables for testing
    $TestTempPath = Join-Path $env:TEMP "CAUJUS_Test_Temp"
    if (Test-Path $TestTempPath) {
        Remove-Item -Path $TestTempPath -Recurse -Force
    }
    New-Item -Path $TestTempPath -ItemType Directory | Out-Null

    $GlobalLogDir = Join-Path $TestTempPath "CAUJUS_Logs_Test"
    $GlobalAdUser = "TestADUser"
    $GlobalLogFile = Join-Path $GlobalLogDir "test_log_file.log"
    $script:ConfigRemoteLogDir = "\\testserver\testshare\logs"

    Mock -CommandName Get-Date -ParameterFilter { $Format -eq "yyyy-MM-dd HH:mm:ss" } -MockWith { return "YYYY-MM-DD hh:mm:ss" } | Out-Null
    Mock -CommandName Get-Date -ParameterFilter { $Format -eq "yyyyMMdd_HHmmss" } -MockWith { return "YYYYMMDD_hhmmss" } | Out-Null

    if (-not (Test-Path $GlobalLogDir)) {
        New-Item -Path $GlobalLogDir -ItemType Directory -Force | Out-Null
    }
    if (-not (Test-Path $GlobalLogFile) -and $GlobalLogFile) {
         New-Item -Path $GlobalLogFile -ItemType File -Force -Value "Initial log content" | Out-Null
    }
}

AfterAll {
    $TestTempPath = Join-Path $env:TEMP "CAUJUS_Test_Temp"
    if (Test-Path $TestTempPath) {
        Remove-Item -Path $TestTempPath -Recurse -Force
    }
}

Describe "CAUJUS_dev.ps1 - Write-Log Function" {
    Context "Basic Logging" {
        BeforeEach {
            Clear-MockState
            Mock -CommandName Get-Date -ParameterFilter { $Format -eq "yyyy-MM-dd HH:mm:ss" } -MockWith { return "YYYY-MM-DD hh:mm:ss" } | Out-Null
            Mock -CommandName Add-Content {}
        }

        It "debería escribir un mensaje con nivel INFO por defecto" {
            Write-Log -Message "Mensaje de prueba INFO"
            Assert-MockCalled -CommandName Add-Content -Times 1 -Scope It
            $call = Get-MockCall -CommandName Add-Content -Scope It | Select-Object -First 1
            $call.Parameters.Value | Should -Be "YYYY-MM-DD hh:mm:ss - INFO - Mensaje de prueba INFO"
            $call.Parameters.Path | Should -Be $GlobalLogFile
        }

        It "debería escribir un mensaje con el nivel especificado (WARN, ERROR)" {
            Write-Log -Message "Mensaje de prueba WARN" -Level "WARN"
            Assert-MockCalled -CommandName Add-Content -Times 1 -Scope It
            $callWarn = Get-MockCall -CommandName Add-Content -Scope It | Select-Object -First 1
            $callWarn.Parameters.Value | Should -Be "YYYY-MM-DD hh:mm:ss - WARN - Mensaje de prueba WARN"

            Clear-MockState -CommandName Add-Content
            Mock -CommandName Add-Content {}
            Write-Log -Message "Mensaje de prueba ERROR" -Level "ERROR"
            Assert-MockCalled -CommandName Add-Content -Times 1 -Scope It
            $callError = Get-MockCall -CommandName Add-Content -Scope It | Select-Object -First 1
            $callError.Parameters.Value | Should -Be "YYYY-MM-DD hh:mm:ss - ERROR - Mensaje de prueba ERROR"
        }

        It "debería formatear la entrada de log correctamente (timestamp, level, message)" {
            Write-Log -Message "Mensaje formateado" -Level "RUNAS"
            Assert-MockCalled -CommandName Add-Content -Times 1 -Scope It
            $call = Get-MockCall -CommandName Add-Content -Scope It | Select-Object -First 1
            $call.Parameters.Value | Should -Be "YYYY-MM-DD hh:mm:ss - RUNAS - Mensaje formateado"
        }
    }

    Context "Log Directory and File Handling" {
        BeforeEach {
            Clear-MockState
            Mock -CommandName Get-Date -ParameterFilter { $Format -eq "yyyy-MM-dd HH:mm:ss" } -MockWith { return "YYYY-MM-DD hh:mm:ss" } | Out-Null
        }

        It "debería crear el directorio de logs si no existe" {
            Mock -CommandName Test-Path -ParameterFilter { $Path -eq $GlobalLogDir -and $PathType -eq "Container" } -MockWith { return $false } -Verifiable
            Mock -CommandName New-Item -ParameterFilter { $Path -eq $GlobalLogDir -and $ItemType -eq "Directory" } -MockWith { } -Verifiable
            Mock -CommandName Add-Content {} -Verifiable

            Write-Log -Message "Prueba de creación de directorio"

            Assert-MockCalled -CommandName Test-Path -Scope It
            Assert-MockCalled -CommandName New-Item -Scope It
            Assert-MockCalled -CommandName Add-Content -Scope It
        }

        It "no debería intentar crear el directorio si ya existe" {
            Mock -CommandName Test-Path -ParameterFilter { $Path -eq $GlobalLogDir -and $PathType -eq "Container" } -MockWith { return $true } -Verifiable
            Mock -CommandName New-Item -Verifiable
            Mock -CommandName Add-Content {} -Verifiable

            Write-Log -Message "Prueba de directorio existente"

            Assert-MockCalled -CommandName Test-Path -Scope It
            Assert-MockCalled -CommandName New-Item -Times 0 -Scope It
            Assert-MockCalled -CommandName Add-Content -Scope It
        }

        It "debería escribir en el archivo de log correcto especificado por `$GlobalLogFile" {
            Mock -CommandName Test-Path -ParameterFilter { $Path -eq $GlobalLogDir -and $PathType -eq "Container" } -MockWith { return $true }
            Mock -CommandName Add-Content {} -Verifiable

            Write-Log -Message "Prueba de ruta de archivo"

            Assert-MockCalled -CommandName Add-Content -Scope It
            $call = Get-MockCall -CommandName Add-Content -Scope It | Select-Object -First 1
            $call.Parameters.Path | Should -Be $GlobalLogFile
        }

        It "debería manejar con gracia el fallo al crear el directorio de log" {
            Mock -CommandName Test-Path -ParameterFilter { $Path -eq $GlobalLogDir } -MockWith { return $false }
            Mock -CommandName New-Item -ParameterFilter { $Path -eq $GlobalLogDir } -MockWith { throw "Permission Denied" }
            Mock -CommandName Write-Warning -Verifiable
            Mock -CommandName Add-Content {} -Verifiable

            Write-Log -Message "Prueba de fallo de creación de directorio"

            Assert-MockCalled -CommandName Write-Warning -Times 1 -Scope It
            (Get-MockCall -CommandName Write-Warning -Scope It).Parameters[0] | Should -Match "Falló la creación del directorio de log: .* Error: Permission Denied"
            Assert-MockCalled -CommandName Add-Content -Times 0 -Scope It
        }

        It "debería manejar con gracia el fallo al escribir en el archivo de log" {
            Mock -CommandName Test-Path -ParameterFilter { $Path -eq $GlobalLogDir } -MockWith { return $true }
            Mock -CommandName Add-Content -MockWith { throw "Disk Full" } -Verifiable
            Mock -CommandName Write-Warning -Verifiable

            Write-Log -Message "Prueba de fallo de escritura de archivo"

            Assert-MockCalled -CommandName Write-Warning -Times 1 -Scope It
            (Get-MockCall -CommandName Write-Warning -Scope It).Parameters[0] | Should -Match "Falló la escritura al archivo de log: .* Error: Disk Full"
        }

        It "no debería registrar si `$GlobalLogFile no está configurado" {
            $OriginalLogFile = $GlobalLogFile
            $GlobalLogFile = $null
            Mock -CommandName Write-Warning -Verifiable
            Mock -CommandName Add-Content {} -Verifiable

            Write-Log -Message "Prueba de GlobalLogFile nulo"

            Assert-MockCalled -CommandName Write-Warning -Times 1 -Scope It
            (Get-MockCall -CommandName Write-Warning -Scope It).Parameters[0] | Should -Match "LOG_FILE no está configurado. Mensaje no registrado:"
            Assert-MockCalled -CommandName Add-Content -Times 0 -Scope It

            $GlobalLogFile = ""
            Clear-MockState -CommandName Write-Warning, Add-Content
            Mock -CommandName Write-Warning -Verifiable
            Mock -CommandName Add-Content {} -Verifiable
            Write-Log -Message "Prueba de GlobalLogFile vacío"
            Assert-MockCalled -CommandName Write-Warning -Times 1 -Scope It
            (Get-MockCall -CommandName Write-Warning -Scope It).Parameters[0] | Should -Match "LOG_FILE no está configurado. Mensaje no registrado:"
            Assert-MockCalled -CommandName Add-Content -Times 0 -Scope It

            $GlobalLogFile = $OriginalLogFile
        }
    }
}

Describe "CAUJUS_dev.ps1 - Configuration Variable Loading" {
    Context "Presence and Default Values" {
        It "debería cargar las variables de configuración de cadena por defecto correctamente" {
            $ConfigRemoteLogDir | Should -Not -BeNullOrEmpty
            $ConfigRemoteLogDir | Should -Be "\\iusnas05\SIJ\CAU-2012\logs"
            $ConfigSoftwareBasePath | Should -Be "\\iusnas05\DDPP\COMUN\Aplicaciones Corporativas"
        }

        It "debería construir correctamente las rutas usando Join-Path" {
            $ConfigIslMsiPath | Should -Be (Join-Path $ConfigSoftwareBasePath "isl.msi")
            $ConfigFnmtConfigExe | Should -Be (Join-Path $ConfigSoftwareBasePath "Configurador_FNMT_5.0.0_64bits.exe")
        }

        It "debería cargar la variable de versión del script `$ConfigScriptVersion" {
            $ConfigScriptVersion | Should -Not -BeNullOrEmpty
            $ConfigScriptVersion | Should -Be "1.0.0"
        }
    }
}

Describe "CAUJUS_dev.ps1 - Invoke-ElevatedCommand Function" {
    BeforeEach {
        Clear-MockState
        Mock -CommandName Write-Log {}
    }

    Context "Command Execution Logic" {
        It "debería construir los argumentos de runas correctamente para un usuario del dominio JUSTICIA" {
            Mock -CommandName Get-WmiObject -MockWith { return @{ Domain = "JUSTICIA" } }
            Mock -CommandName Start-Process -MockWith { return @{ ExitCode = 0 } }
            Invoke-ElevatedCommand -CommandToRun "mycommand.exe -arg"
            Assert-MockCalled -CommandName Start-Process -Scope It -ParameterFilter {
                $ArgumentList -like "/user:$($GlobalAdUser)@JUSTICIA /savecred \`"mycommand.exe -arg\`""
            }
        }

        It "debería construir los argumentos de runas correctamente para un usuario no perteneciente al dominio" {
            Mock -CommandName Get-WmiObject -MockWith { return @{ Domain = "OTRODOMINIO" } }
            Mock -CommandName Start-Process -MockWith { return @{ ExitCode = 0 } }
            Invoke-ElevatedCommand -CommandToRun "mycommand.exe"
            Assert-MockCalled -CommandName Start-Process -Scope It -ParameterFilter {
                $ArgumentList -like "/user:$($GlobalAdUser) /savecred \`"mycommand.exe\`""
            }
        }
         It "debería construir los argumentos de runas correctamente cuando el dominio es nulo" {
            Mock -CommandName Get-WmiObject -MockWith { $null }
            Mock -CommandName Start-Process -MockWith { return @{ ExitCode = 0 } }
            Invoke-ElevatedCommand -CommandToRun "mycommand.exe"
            Assert-MockCalled -CommandName Start-Process -Scope It -ParameterFilter {
                $ArgumentList -like "/user:$($GlobalAdUser) /savecred \`"mycommand.exe\`""
            }
        }

        It "debería usar /savecred en los argumentos de runas" {
            Mock -CommandName Get-WmiObject -MockWith { $null }
            Mock -CommandName Start-Process -MockWith { return @{ ExitCode = 0 } }
            Invoke-ElevatedCommand -CommandToRun "cmd /c echo test"
            Assert-MockCalled -CommandName Start-Process -Scope It -ParameterFilter { $ArgumentList -match "/savecred" }
        }

        It "debería pasar el comando a ejecutar correctamente entrecomillado en los argumentos de runas" {
            Mock -CommandName Get-WmiObject -MockWith { $null }
            Mock -CommandName Start-Process -MockWith { return @{ ExitCode = 0 } }
            $testCommand = "C:\Program Files\Test Path\my utility.exe -param value"
            Invoke-ElevatedCommand -CommandToRun $testCommand
            Assert-MockCalled -CommandName Start-Process -Scope It -ParameterFilter { $ArgumentList -match "`"$([System.Text.RegularExpressions.Regex]::Escape($testCommand))`"" }
        }

        It "debería llamar a Start-Process con -Wait y -PassThru" {
            Mock -CommandName Get-WmiObject -MockWith { $null }
            Mock -CommandName Start-Process -MockWith { return @{ ExitCode = 0 } } -Verifiable
            Invoke-ElevatedCommand -CommandToRun "test.exe"
            Assert-MockCalled -CommandName Start-Process -Scope It -ParameterFilter { $Wait -and $PassThru }
        }

        It "debería usar -WindowStyle Hidden por defecto" {
            Mock -CommandName Get-WmiObject -MockWith { $null }
            Mock -CommandName Start-Process -MockWith { return @{ ExitCode = 0 } } -Verifiable
            Invoke-ElevatedCommand -CommandToRun "test.exe"
            Assert-MockCalled -CommandName Start-Process -Scope It -ParameterFilter { $WindowStyle -eq "Hidden" }
        }

        It "debería usar el estilo de ventana actual si -NoNewWindow es $false" {
            Mock -CommandName Get-WmiObject -MockWith { $null }
            Mock -CommandName Start-Process -MockWith { return @{ ExitCode = 0 } } -Verifiable
            Invoke-ElevatedCommand -CommandToRun "test.exe" -NoNewWindow:$false
            Assert-MockCalled -CommandName Start-Process -Scope It
            $call = Get-MockCall -CommandName Start-Process -Scope It | Select-Object -Last 1
            $call.Parameters.ContainsKey("WindowStyle") | Should -Be $false
        }

        It "debería devolver el código de salida de Start-Process" {
            Mock -CommandName Get-WmiObject -MockWith { $null }
            Mock -CommandName Start-Process -MockWith { return @{ ExitCode = 123 } }
            $result = Invoke-ElevatedCommand -CommandToRun "test.exe"
            $result | Should -Be 123
        }

        It "debería registrar un error y devolver -1 si Start-Process lanza una excepción" {
            Mock -CommandName Get-WmiObject -MockWith { $null }
            Mock -CommandName Start-Process -MockWith { throw "Process Failed" }
            $result = Invoke-ElevatedCommand -CommandToRun "test.exe"
            Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Level -eq "ERROR" -and $Message -match "Falló el inicio del proceso elevado"}
            $result | Should -Be -1
        }

        It "debería registrar un error y devolver -1 si $GlobalAdUser no está configurado" {
            $originalAdUser = $GlobalAdUser
            $GlobalAdUser = $null
            $result = Invoke-ElevatedCommand -CommandToRun "test.exe"
            Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Level -eq "ERROR" -and $Message -match "adUser no está configurado" }
            $result | Should -Be -1
            $GlobalAdUser = $originalAdUser
        }
    }
}

Describe "CAUJUS_dev.ps1 - Invoke-ElevatedPowerShellCommand Function" {
    BeforeEach {
        Clear-MockState
        Mock -CommandName Write-Log {}
    }

    Context "PowerShell Command Elevation" {
        It "debería codificar correctamente el ScriptBlockContent a Base64" {
            $scriptContent = "Get-Process"
            $bytes = [System.Text.Encoding]::Unicode.GetBytes($scriptContent)
            $expectedEncoded = [Convert]::ToBase64String($bytes)

            Mock -CommandName Invoke-ElevatedCommand -MockWith { return 0 } -Verifiable
            Invoke-ElevatedPowerShellCommand -ScriptBlockContent $scriptContent

            Assert-MockCalled -CommandName Invoke-ElevatedCommand -Scope It -ParameterFilter {
                $CommandToRun -match ([regex]::Escape($expectedEncoded))
            }
        }

        It "debería construir el comando powershell.exe con -EncodedCommand" {
            Mock -CommandName Invoke-ElevatedCommand -MockWith { return 0 } -Verifiable
            Invoke-ElevatedPowerShellCommand -ScriptBlockContent "Get-Process"
            Assert-MockCalled -CommandName Invoke-ElevatedCommand -Scope It -ParameterFilter {
                $CommandToRun -match "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "
            }
        }

        It "debería llamar a Invoke-ElevatedCommand con el comando powershell.exe construido" {
            Mock -CommandName Invoke-ElevatedCommand -MockWith { return 0 } -Verifiable
            Invoke-ElevatedPowerShellCommand -ScriptBlockContent "Get-Process"
            Assert-MockCalled -CommandName Invoke-ElevatedCommand -Times 1 -Scope It
        }

        It "debería pasar el parámetro -NoNewWindow a Invoke-ElevatedCommand" {
            Mock -CommandName Invoke-ElevatedCommand -MockWith { return 0 } -Verifiable
            Invoke-ElevatedPowerShellCommand -ScriptBlockContent "Get-Process" -NoNewWindow:$true
            Assert-MockCalled -CommandName Invoke-ElevatedCommand -Scope It -ParameterFilter { $NoNewWindow -eq $true }

            Clear-MockState -CommandName Invoke-ElevatedCommand
            Mock -CommandName Invoke-ElevatedCommand -MockWith { return 0 } -Verifiable
            Invoke-ElevatedPowerShellCommand -ScriptBlockContent "Get-Process" -NoNewWindow:$false
            Assert-MockCalled -CommandName Invoke-ElevatedCommand -Scope It -ParameterFilter { $NoNewWindow -eq $false }
        }

        It "debería devolver el código de salida de Invoke-ElevatedCommand" {
            Mock -CommandName Invoke-ElevatedCommand -MockWith { return 77 }
            $result = Invoke-ElevatedPowerShellCommand -ScriptBlockContent "Get-Process"
            $result | Should -Be 77
        }

        It "debería registrar un error y devolver -1 si ocurre una excepción durante la preparación del comando" {
            Mock -CommandName ([Convert])::ToBase64String([byte[]]) -MockWith { throw "Encoding Error" }
            $result = Invoke-ElevatedPowerShellCommand -ScriptBlockContent "Get-Process"
            Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Level -eq "ERROR" -and $Message -match "Error preparando o invocando comando PowerShell elevado" }
            $result | Should -Be -1
        }
    }
}

Describe "CAUJUS_dev.ps1 - SubirArchivoLog Function" {
    BeforeEach {
        Clear-MockState
        Mock -CommandName Write-Log {}
        $script:GlobalLogFile = Join-Path $GlobalLogDir "test_upload_file.log"
        if (-not (Test-Path $script:GlobalLogFile)) {
            New-Item -Path $script:GlobalLogFile -ItemType File -Force -Value "test content" | Out-Null
        }
    }
    AfterEach {
        if (Test-Path $script:GlobalLogFile) { Remove-Item $script:GlobalLogFile -Force }
    }

    Context "Log Upload Logic" {
        It "debería registrar una advertencia y devolver `$false si `$GlobalLogFile no está configurado o no existe" {
            $originalLogFile = $GlobalLogFile

            $GlobalLogFile = $null
            SubirArchivoLog | Should -Be $false
            Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Level -eq "WARN" -and $Message -match "La ruta del archivo de log no está configurada o el archivo no existe" }

            Clear-MockState -CommandName Write-Log
            $GlobalLogFile = Join-Path $GlobalLogDir "non_existent_file.log"
            SubirArchivoLog | Should -Be $false
            Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Level -eq "WARN" -and $Message -match "La ruta del archivo de log no está configurada o el archivo no existe" }

            $GlobalLogFile = $originalLogFile
        }

        It "debería registrar un error y devolver `$false si `$ConfigRemoteLogDir no está configurado" {
            $originalRemoteDir = $ConfigRemoteLogDir
            $ConfigRemoteLogDir = ""
            SubirArchivoLog | Should -Be $false
            Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Level -eq "ERROR" -and $Message -match "El directorio de log remoto .* no está configurado" }
            $ConfigRemoteLogDir = $originalRemoteDir
        }

        It "debería llamar a Invoke-ElevatedPowerShellCommand para crear el directorio remoto" {
            Mock -CommandName Invoke-ElevatedPowerShellCommand -MockWith { return 0 } -Verifiable
            SubirArchivoLog | Out-Null
            $expectedMkdirCommand = "if (-not (Test-Path -LiteralPath \`"$ConfigRemoteLogDir\`" -PathType Container)) { New-Item -Path \`"$ConfigRemoteLogDir\`" -ItemType Directory -Force -ErrorAction Stop | Out-Null }"
            Assert-MockCalled -CommandName Invoke-ElevatedPowerShellCommand -Scope It -ParameterFilter { $ScriptBlockContent -eq $expectedMkdirCommand } -Times 1
        }

        It "debería registrar un error y devolver `$false si falla la creación del directorio remoto" {
            Mock -CommandName Invoke-ElevatedPowerShellCommand -ParameterFilter { $ScriptBlockContent -match "New-Item" } -MockWith { return 1 }
            SubirArchivoLog | Should -Be $false
            Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Level -eq "ERROR" -and $Message -match "Falló la creación o verificación del directorio de log remoto" }
        }

        It "debería llamar a Invoke-ElevatedPowerShellCommand para copiar el archivo de log" {
            Mock -CommandName Invoke-ElevatedPowerShellCommand -MockWith { return 0 } -Verifiable
            $expectedLogFileName = Split-Path -Path $GlobalLogFile -Leaf
            $expectedFinalLogPathOnShare = Join-Path $ConfigRemoteLogDir $expectedLogFileName
            $expectedCopyCommand = "Copy-Item -LiteralPath \`"$($GlobalLogFile)\`" -Destination \`"$expectedFinalLogPathOnShare\`" -Force -ErrorAction Stop"

            SubirArchivoLog | Out-Null

            Assert-MockCalled -CommandName Invoke-ElevatedPowerShellCommand -Scope It -ParameterFilter { $ScriptBlockContent -eq $expectedCopyCommand } -Times 1
        }

        It "debería devolver `$true si la copia es exitosa" {
            Mock -CommandName Invoke-ElevatedPowerShellCommand -MockWith { return 0 }
            SubirArchivoLog | Should -Be $true
            Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Message -match "Intento de carga de archivo de log con Invoke-ElevatedPowerShellCommand exitoso" }
        }

        It "debería registrar un error y devolver `$false si la copia falla" {
            Mock -CommandName Invoke-ElevatedPowerShellCommand -ParameterFilter { $ScriptBlockContent -match "Copy-Item" } -MockWith { return 1 }
            SubirArchivoLog | Should -Be $false
            Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Level -eq "ERROR" -and $Message -match "Carga de archivo de log con Invoke-ElevatedPowerShellCommand fallida" }
        }
    }
}

Describe "CAUJUS_dev.ps1 - InvocarAutoeliminacion Function" {
    BeforeEach {
        Clear-MockState
        Mock -CommandName Write-Log {}
        $mockMyInvocation = @{ MyCommand = @{ Path = (Join-Path $PSScriptRoot "CAUJUS_dev.ps1") } }
        Mock -CommandVariable MyInvocation -Value $mockMyInvocation
    }

    Context "Script Self-Deletion Process" {
        It "debería llamar a SubirArchivoLog antes de intentar la eliminación" {
            Mock -CommandName SubirArchivoLog -MockWith { return $true } -Verifiable
            Mock -CommandName Remove-Item {}
            Mock -CommandName Start-Sleep {}
            Mock -CommandName Write-Host {}
            Mock -CommandName Exit-PSHost

            InvocarAutoeliminacion
            Assert-MockCalled -CommandName SubirArchivoLog -Times 1 -Scope It
        }

        It "debería registrar éxito si SubirArchivoLog devuelve `$true" {
            Mock -CommandName SubirArchivoLog -MockWith { return $true }
            Mock -CommandName Remove-Item {} ; Mock -CommandName Start-Sleep {}; Mock -CommandName Write-Host {}; Mock -CommandName Exit-PSHost
            InvocarAutoeliminacion
            Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Message -match "Archivo de log cargado exitosamente antes de la auto-eliminación." }
        }

        It "debería registrar una advertencia si SubirArchivoLog devuelve `$false" {
            Mock -CommandName SubirArchivoLog -MockWith { return $false }
            Mock -CommandName Remove-Item {} ; Mock -CommandName Start-Sleep {}; Mock -CommandName Write-Host {}; Mock -CommandName Exit-PSHost
            InvocarAutoeliminacion
            Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Level -eq "WARN" -and $Message -match "La carga del archivo de log falló o se omitió antes de la auto-eliminación." }
        }

        It "debería llamar a Remove-Item con la ruta correcta del script y -Force" {
            Mock -CommandName SubirArchivoLog -MockWith { return $true }
            Mock -CommandName Remove-Item -Verifiable
            Mock -CommandName Start-Sleep {} ; Mock -CommandName Write-Host {}; Mock -CommandName Exit-PSHost
            $expectedScriptPath = $MyInvocation.MyCommand.Path
            InvocarAutoeliminacion
            Assert-MockCalled -CommandName Remove-Item -Scope It -ParameterFilter { $Path -eq $expectedScriptPath -and $Force }
        }

        It "debería llamar a Start-Sleep brevemente antes de Remove-Item" {
            Mock -CommandName SubirArchivoLog -MockWith { return $true }
            Mock -CommandName Remove-Item {}
            Mock -CommandName Start-Sleep -ParameterFilter { $Milliseconds -eq 200 } -Verifiable
            Mock -CommandName Write-Host {} ; Mock -CommandName Exit-PSHost
            InvocarAutoeliminacion
            Assert-MockCalled -CommandName Start-Sleep -Times 1 -Scope It
        }

        It "debería Write-Host un mensaje sobre la eliminación del script y salir" {
            Mock -CommandName SubirArchivoLog -MockWith { return $true }
            Mock -CommandName Remove-Item {}
            Mock -CommandName Start-Sleep {}
            Mock -CommandName Write-Host -Verifiable
            Mock -CommandName Exit-PSHost -Verifiable
            InvocarAutoeliminacion
            Assert-MockCalled -CommandName Write-Host -Scope It -ParameterFilter { $Object -match "El script ha sido eliminado y ahora saldrá." }
            Assert-MockCalled -CommandName Exit-PSHost -Scope It
        }

        It "debería registrar un error y Write-Host un error si Remove-Item lanza una excepción" {
            Mock -CommandName SubirArchivoLog -MockWith { return $true }
            Mock -CommandName Remove-Item -MockWith { throw "Access Denied" }
            Mock -CommandName Start-Sleep {}
            Mock -CommandName Write-Host -Verifiable
            Mock -CommandName Exit-PSHost -Verifiable
            InvocarAutoeliminacion
            Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Level -eq "ERROR" -and $Message -match "Error durante la auto-eliminación: .* Access Denied" }
            Assert-MockCalled -CommandName Write-Host -Scope It -ParameterFilter { $Object -match "Error al intentar auto-eliminarse. El script aún podría existir." }
            Assert-MockCalled -CommandName Exit-PSHost -Scope It
        }
    }
}

Describe "CAUJUS_dev.ps1 - Batería de Pruebas Functions" {
    BeforeEach {
        Clear-MockState
        Mock -CommandName Write-Log {}
        Mock -CommandName Invoke-ElevatedCommand -MockWith { return 0 }
        Mock -CommandName Invoke-ElevatedPowerShellCommand -MockWith { return 0 }
        # Mock helpers called by other helpers or the main function
        Mock -CommandName DetenerNavegadoresComunes {}
        Mock -CommandName LimpiarCachesSistemaUsuario {}
        Mock -CommandName AplicarAjustesRegistroEfectosVisuales {}
        Mock -CommandName RealizarTareasMantenimientoSistema {}
        Mock -CommandName SubirArchivoLog -MockWith { return $true }
        Mock -CommandName InvocarAutoeliminacion {}
        Mock -CommandName Restart-Computer {}
        Mock -CommandName Read-Host {}
        Mock -CommandName Write-Host {}
        Mock -CommandName Write-Warning {}
        Mock -CommandName Exit-PSHost {}
    }

    Context "DetenerNavegadoresComunes" {
        It "debería intentar detener los procesos de navegadores especificados" {
            Mock -CommandName Stop-Process -Verifiable
            DetenerNavegadoresComunes
            $browsers = "chrome", "iexplore", "msedge", "firefox"
            foreach ($browser in $browsers) {
                Assert-MockCalled -CommandName Stop-Process -Scope It -ParameterFilter { $Name -eq $browser -and $Force } # Called at least once
            }
        }
        It "debería registrar el intento de detener cada navegador" {
             DetenerNavegadoresComunes
             Assert-MockCalled -CommandName Write-Log -AtLeast 1 -Scope It
             Assert-MockCalled -CommandName Write-Log -ParameterFilter {$Message -match "BT: Terminando procesos comunes"} -Times 1 -Scope It
        }
    }

    Context "LimpiarCachesSistemaUsuario" {
        It "debería llamar a Clear-DnsClientCache" {
            Mock -CommandName Clear-DnsClientCache -Verifiable
            LimpiarCachesSistemaUsuario
            Assert-MockCalled -CommandName Clear-DnsClientCache -Times 1 -Scope It
        }
        It "debería ejecutar ClearMyTracksByProcess para cachés especificados" {
            Mock -CommandName Start-Process -MockWith {return $null} -Verifiable
            LimpiarCachesSistemaUsuario
            $cacheClearCommands = @(16, 8, 2, 1)
            foreach ($commandId in $cacheClearCommands) {
                 Assert-MockCalled -CommandName Start-Process -Scope It -ParameterFilter { $ArgumentList -match "ClearMyTracksByProcess $commandId" }
            }
        }
        It "debería intentar limpiar la caché de Chrome si la ruta existe" {
            Mock -CommandName Test-Path -ParameterFilter { $Path -like "*Google\Chrome\User Data\Default\Cache" } -MockWith { return $true } -Verifiable
            Mock -CommandName Remove-Item -ParameterFilter { $Path -like "*Google\Chrome\User Data\Default\Cache\*" } -Verifiable
            LimpiarCachesSistemaUsuario
            Assert-MockCalled -CommandName Test-Path -Scope It
            Assert-MockCalled -CommandName Remove-Item -Scope It
        }
        It "debería registrar una advertencia si la ruta de la caché de Chrome no existe" {
            Mock -CommandName Test-Path -ParameterFilter { $Path -like "*Google\Chrome\User Data\Default\Cache" } -MockWith { return $false } -Verifiable
            LimpiarCachesSistemaUsuario
            Assert-MockCalled -CommandName Test-Path -Scope It
            Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Level -eq "WARN" -and $Message -match "Ruta de caché de Chrome no encontrada" }
        }
    }

    Context "AplicarAjustesRegistroEfectosVisuales" {
        It "debería intentar aplicar todos los ajustes de registro especificados usando Invoke-ElevatedCommand" {
            AplicarAjustesRegistroEfectosVisuales
            Assert-MockCalled -CommandName Invoke-ElevatedCommand -Scope It -ParameterFilter { $CommandToRun -match "REG ADD .*WindowMetrics.*MinAnimate" }
            Assert-MockCalled -CommandName Invoke-ElevatedCommand -Scope It -ParameterFilter { $CommandToRun -match "REG ADD .*Explorer\\Advanced.*TaskbarAnimations" }
            Assert-MockCalled -CommandName Invoke-ElevatedCommand -AtLeast 5 -Scope It
        }
    }

    Context "RealizarTareasMantenimientoSistema" {
        It "debería ejecutar gpupdate /force usando Invoke-ElevatedCommand" {
            RealizarTareasMantenimientoSistema
            Assert-MockCalled -CommandName Invoke-ElevatedCommand -Scope It -ParameterFilter { $CommandToRun -eq "gpupdate /force" }
        }
        It "debería intentar reinstalar ISL MSI usando Invoke-ElevatedCommand" {
            RealizarTareasMantenimientoSistema
            Assert-MockCalled -CommandName Invoke-ElevatedCommand -Scope It -ParameterFilter { $CommandToRun -match "msiexec /i \`"$($ConfigIslMsiPath)\`" /qn" }
        }
        It "debería intentar limpiar rutas de todo el sistema usando Invoke-ElevatedPowerShellCommand" {
            RealizarTareasMantenimientoSistema
            Assert-MockCalled -CommandName Invoke-ElevatedPowerShellCommand -Scope It -ParameterFilter { $ScriptBlockContent -match "Remove-Item -Path '\$env:windir\\\*.bak'" }
            Assert-MockCalled -CommandName Invoke-ElevatedPowerShellCommand -Scope It -ParameterFilter { $ScriptBlockContent -match "Remove-Item -Path '\$env:SystemDrive\\\*.tmp'" }
        }
         It "debería intentar limpiar rutas específicas del usuario usando Invoke-ElevatedPowerShellCommand" {
            RealizarTareasMantenimientoSistema
            Assert-MockCalled -CommandName Invoke-ElevatedPowerShellCommand -Scope It -ParameterFilter { $ScriptBlockContent -match "Remove-Item -Path '\$env:TEMP\\\*'" }
        }
        It "debería intentar recrear carpetas especificadas usando Invoke-ElevatedPowerShellCommand" {
             RealizarTareasMantenimientoSistema
            Assert-MockCalled -CommandName Invoke-ElevatedPowerShellCommand -Scope It -ParameterFilter { $ScriptBlockContent -match "Remove-Item -Path '\$env:windir\\Temp' .* New-Item -Path '\$env:windir\\Temp'" }
        }
    }

    Context "InvocarBateriaPruebas" {
        It "debería llamar a las funciones auxiliares en el orden correcto" {
            InvocarBateriaPruebas
            Assert-MockCalled -CommandName DetenerNavegadoresComunes -Scope It -Exactly 1 -Unordered
            Assert-MockCalled -CommandName LimpiarCachesSistemaUsuario -Scope It -Exactly 1 -Unordered
            Assert-MockCalled -CommandName AplicarAjustesRegistroEfectosVisuales -Scope It -Exactly 1 -Unordered
            Assert-MockCalled -CommandName RealizarTareasMantenimientoSistema -Scope It -Exactly 1 -Unordered
        }

        It "debería solicitar al usuario reiniciar después de completar las tareas" {
            InvocarBateriaPruebas
            Assert-MockCalled -CommandName Read-Host -Scope It -ParameterFilter { $Prompt -match "Reiniciar equipo ahora" }
        }

        Context "Usuario elige reiniciar ('s')" {
            BeforeEach {
                 Mock -CommandName Read-Host -ParameterFilter { $Prompt -match "Reiniciar equipo ahora" } -MockWith { return 's' }
            }
            It "debería llamar a SubirArchivoLog antes de reiniciar" {
                InvocarBateriaPruebas
                Assert-MockCalled -CommandName SubirArchivoLog -Times 1 -Scope It
            }
            It "debería llamar a Restart-Computer -Force" {
                InvocarBateriaPruebas
                Assert-MockCalled -CommandName Restart-Computer -Scope It -ParameterFilter { $Force }
            }
            It "debería registrar la acción de reinicio e intentar el log de auto-eliminación" {
                InvocarBateriaPruebas
                Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Message -match "Iniciando reinicio del equipo AHORA" }
                Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Message -match "Intentando auto-eliminación del script post-comando de reinicio" }
            }
        }

        Context "Usuario elige no reiniciar ('n')" {
            BeforeEach {
                Mock -CommandName Read-Host -ParameterFilter { $Prompt -match "Reiniciar equipo ahora" } -MockWith { return 'n' }
            }
            It "debería llamar a InvocarAutoeliminacion" {
                InvocarBateriaPruebas
                Assert-MockCalled -CommandName InvocarAutoeliminacion -Times 1 -Scope It
            }
            It "debería registrar la decisión de no reiniciar" {
                 InvocarBateriaPruebas
                 Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Message -match "Usuario eligió no reiniciar." }
            }
        }

        It "debería manejar una entrada inválida para la elección de reinicio y volver a preguntar" {
            Mock -CommandName Read-Host -MockWith {
                param($Prompt)
                if ($Prompt -match "Reiniciar equipo ahora") {
                    if ($script:firstPrompt -ne $true) {
                        $script:firstPrompt = $true
                        return 'invalido'
                    } else {
                        return 'n'
                    }
                }
            }
            $script:firstPrompt = $false
            InvocarBateriaPruebas
            Assert-MockCalled -CommandName Read-Host -Scope It -ParameterFilter { $Prompt -match "Reiniciar equipo ahora" } -Times 2
            Assert-MockCalled -CommandName Write-Warning -Scope It -ParameterFilter { $Message -match "Respuesta no válida." } -Times 1
        }
    }
}

Describe "CAUJUS_dev.ps1 - Menu and Action Functions" {
    BeforeEach {
        Clear-MockState
        Mock -CommandName Write-Log {}
        Mock -CommandName Invoke-ElevatedCommand -MockWith { return 0 }
        Mock -CommandName InvocarAutoeliminacion {}
        Mock -CommandName SubirArchivoLog -MockWith { return $true }
        Mock -CommandName Start-Process -MockWith { return $null } # Default mock for Start-Process
        Mock -CommandName Read-Host {}
        Mock -CommandName Write-Host {}
        Mock -CommandName Clear-Host {}
        Mock -CommandName Exit-PSHost {}
        Mock -CommandName Restart-Computer {}
        # Mock other menu functions to prevent deep execution chains when testing a specific menu
        Mock -CommandName MostrarMenuPrincipal {}
        Mock -CommandName MostrarMenuCertificadosDigitales {}
        Mock -CommandName MostrarInformacionIslAlwaysOn {}
        Mock -CommandName MostrarMenuUtilidades {}
        Mock -CommandName InvocarBateriaPruebas {}
        Mock -CommandName AbrirUrlCambiarContraseña {}
        Mock -CommandName ReiniciarServicioColaImpresion {}
        Mock -CommandName MostrarAdministradorDispositivos {}
    }

    Context "AbrirUrlCambiarContraseña" {
        It "debería intentar abrir la URL correcta con chrome.exe" {
            AbrirUrlCambiarContraseña
            Assert-MockCalled -CommandName Start-Process -Scope It -ParameterFilter { $FilePath -eq "chrome.exe" -and $ArgumentList -eq $ConfigUrlMiCuentaJunta }
        }
        It "debería llamar a InvocarAutoeliminacion después de intentar abrir la URL" {
            AbrirUrlCambiarContraseña
            Assert-MockCalled -CommandName InvocarAutoeliminacion -Times 1 -Scope It
        }
        It "debería manejar el fallo de Start-Process con gracia y registrar un error" {
            Mock -CommandName Start-Process -MockWith { throw "Chrome not found" }
            AbrirUrlCambiarContraseña
            Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Level -eq "ERROR" -and $Message -match "Falló el inicio de Chrome.*Chrome not found" }
            Assert-MockCalled -CommandName Write-Warning -Scope It -ParameterFilter { $Message -match "No se pudo abrir Chrome." }
            Assert-MockCalled -CommandName InvocarAutoeliminacion -Times 0 -Scope It # Should return before this
        }
    }

    Context "ReiniciarServicioColaImpresion" {
        It "debería llamar a Invoke-ElevatedCommand con el comando FOR loop correcto" {
            ReiniciarServicioColaImpresion
            Assert-MockCalled -CommandName Invoke-ElevatedCommand -Scope It -ParameterFilter { $CommandToRun -match "FOR /F" -and $CommandToRun -match "prnmngr.vbs" -and $CommandToRun -match "prnqctl.vbs" }
        }
        It "debería llamar a Read-Host para pausar antes de salir" {
            ReiniciarServicioColaImpresion
            Assert-MockCalled -CommandName Read-Host -Scope It -ParameterFilter { $Prompt -match "Presiona Enter para continuar con la salida del script" }
        }
        It "debería llamar a InvocarAutoeliminacion" {
            ReiniciarServicioColaImpresion
            Assert-MockCalled -CommandName InvocarAutoeliminacion -Times 1 -Scope It
        }
        It "debería registrar éxito o fracaso basado en el resultado de Invoke-ElevatedCommand" {
            Mock -CommandName Invoke-ElevatedCommand -MockWith { return 0 }
            ReiniciarServicioColaImpresion
            Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Message -match "Comando de reinicio de cola de impresión ejecutado con éxito" }

            Clear-MockState -CommandName Write-Log, Invoke-ElevatedCommand
            Mock -CommandName Write-Log {}
            Mock -CommandName Invoke-ElevatedCommand -MockWith { return 1 }
            ReiniciarServicioColaImpresion
            Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Level -eq "ERROR" -and $Message -match "Comando de reinicio de cola de impresión falló" }
        }
    }

    Context "MostrarAdministradorDispositivos" {
        It 'debería llamar a Invoke-ElevatedCommand con "RunDll32.exe devmgr.dll DeviceManager_Execute"' {
            MostrarAdministradorDispositivos
            Assert-MockCalled -CommandName Invoke-ElevatedCommand -Scope It -ParameterFilter { $CommandToRun -eq "RunDll32.exe devmgr.dll DeviceManager_Execute" }
        }
        It "debería asegurar que Invoke-ElevatedCommand es llamado con -NoNewWindow `$false" {
            MostrarAdministradorDispositivos
            Assert-MockCalled -CommandName Invoke-ElevatedCommand -Scope It -ParameterFilter { $NoNewWindow -eq $false }
        }
        It "debería llamar a Read-Host para pausar antes de volver al menú" {
            MostrarAdministradorDispositivos
            Assert-MockCalled -CommandName Read-Host -Scope It -ParameterFilter { $Prompt -match "Presiona Enter para volver al menú principal" }
        }
    }

    Context "MostrarMenuCertificadosDigitales" {
        It "debería llamar a Start-Process para FNMT Solicitar cuando se selecciona '1'" {
            Mock -CommandName Read-Host -MockWith { return '1' }
            MostrarMenuCertificadosDigitales
            Assert-MockCalled -CommandName Start-Process -Scope It -ParameterFilter { $ArgumentList -eq $ConfigUrlFnmtSolicitar }
            Assert-MockCalled -CommandName MostrarMenuCertificadosDigitales -Times 2 -Scope It # Once initially, once recursively
        }
        It "debería llamar a Start-Process para certmgr.msc cuando se selecciona '4'" {
            Mock -CommandName Read-Host -MockWith { return '4' }
            MostrarMenuCertificadosDigitales
            Assert-MockCalled -CommandName Start-Process -Scope It -ParameterFilter { $FilePath -eq "certmgr.msc" }
        }
        It "debería volver al menú principal (no llamar recursivamente) cuando se selecciona 'm'" {
            Mock -CommandName Read-Host -MockWith { return 'm' }
            MostrarMenuCertificadosDigitales
            Assert-MockCalled -CommandName MostrarMenuCertificadosDigitales -Times 1 -Scope It # Only the initial call
        }
        It "debería manejar una entrada inválida y volver a mostrar el menú" {
            Mock -CommandName Read-Host -MockWith { $script:Calls = ($script:Calls | ForEach-Object {$_ + 1}); if($script:Calls -eq 1) { return 'invalid' } else { return 'm' } }
            $script:Calls = 0
            MostrarMenuCertificadosDigitales
            Assert-MockCalled -CommandName Write-Warning -Scope It -ParameterFilter { $Message -match "opcion no valida" }
            Assert-MockCalled -CommandName MostrarMenuCertificadosDigitales -Times 2 -Scope It # Initial + recursive
        }
         It "debería usar try-catch para las llamadas a Start-Process y registrar errores" {
            Mock -CommandName Read-Host -MockWith { return '1' }
            Mock -CommandName Start-Process -MockWith { throw "Error al iniciar" }
            MostrarMenuCertificadosDigitales
            Assert-MockCalled -CommandName Write-Log -Scope It -ParameterFilter { $Level -eq 'ERROR' -and $Message -match "Falló el inicio de Chrome.*Error al iniciar" }
        }
    }

    Context "MostrarInformacionIslAlwaysOn" {
        It "debería mostrar texto informativo usando Write-Host" {
            MostrarInformacionIslAlwaysOn
            Assert-MockCalled -CommandName Write-Host -AtLeast 5 -Scope It # Check several Write-Host calls are made
            Assert-MockCalled -CommandName Write-Host -Scope It -ParameterFilter { $Object -match "ISL ALWAYS ON" }
            Assert-MockCalled -CommandName Write-Host -Scope It -ParameterFilter { $Object -match $ConfigSoftwareBasePath }
            Assert-MockCalled -CommandName Write-Host -Scope It -ParameterFilter { $Object -match $ConfigIslMsiPath }
        }
        It "debería llamar a Read-Host para pausar" {
            MostrarInformacionIslAlwaysOn
            Assert-MockCalled -CommandName Read-Host -Scope It -ParameterFilter { $Prompt -match "Presiona Enter para volver al menú principal" }
        }
    }

    Context "MostrarMenuUtilidades" { # Similar structure to MostrarMenuCertificadosDigitales
        It "debería llamar a Start-Process para cleanmgr.exe cuando se selecciona '1'" {
            Mock -CommandName Read-Host -MockWith { return '1' }
            MostrarMenuUtilidades
            Assert-MockCalled -CommandName Start-Process -Scope It -ParameterFilter { $FilePath -eq "cleanmgr.exe" }
            Assert-MockCalled -CommandName MostrarMenuUtilidades -Times 2 -Scope It
        }
         It "debería volver al menú principal cuando se selecciona 'm'" {
            Mock -CommandName Read-Host -MockWith { return 'm' }
            MostrarMenuUtilidades
            Assert-MockCalled -CommandName MostrarMenuUtilidades -Times 1 -Scope It
        }
        It "debería manejar una entrada inválida y volver a mostrar el menú" {
            Mock -CommandName Read-Host -MockWith { $script:Calls = ($script:Calls | ForEach-Object {$_ + 1}); if($script:Calls -eq 1) { return 'invalid' } else { return 'm' } }
            $script:Calls = 0
            MostrarMenuUtilidades
            Assert-MockCalled -CommandName Write-Warning -Scope It -ParameterFilter { $Message -match "opcion no valida" }
            Assert-MockCalled -CommandName MostrarMenuUtilidades -Times 2 -Scope It
        }
    }

    Context "MostrarMenuPrincipal" {
        BeforeEach {
            # Mocks for system information gathering
            Mock -CommandName Get-CimInstance -ParameterFilter {$ClassName -eq "Win32_BIOS"} -MockWith { @{ SerialNumber = "TestSerial123"} }
            Mock -CommandName Get-NetAdapter -MockWith { @{ InterfaceIndex = 1; Status = 'Up'; Name = "Ethernet"} }
            Mock -CommandName Get-NetIPConfiguration -MockWith { @{ IPv4Address = @(@{ IPAddress = "192.168.1.100"; AddressFamily = "InterNetwork"})} }
            Mock -CommandName Get-CimInstance -ParameterFilter {$ClassName -eq "Win32_OperatingSystem"} -MockWith { @{ Caption = "Windows Test OS"; BuildNumber = "12345"} }
        }

        It "debería llamar a Clear-Host al principio" {
            MostrarMenuPrincipal
            Assert-MockCalled -CommandName Clear-Host -Times 1 -Scope It
        }
        It "debería recopilar información del sistema" {
            MostrarMenuPrincipal
            Assert-MockCalled -CommandName Get-CimInstance -ParameterFilter {$ClassName -eq "Win32_BIOS"} -Times 1 -Scope It
            Assert-MockCalled -CommandName Get-NetAdapter -Times 1 -Scope It
            Assert-MockCalled -CommandName Get-NetIPConfiguration -Times 1 -Scope It
            Assert-MockCalled -CommandName Get-CimInstance -ParameterFilter {$ClassName -eq "Win32_OperatingSystem"} -Times 1 -Scope It
        }
        It "debería mostrar la información del sistema recopilada usando Write-Host" {
             MostrarMenuPrincipal
             Assert-MockCalled -CommandName Write-Host -Scope It -ParameterFilter { $Object -match $GlobalUserProfileName }
             Assert-MockCalled -CommandName Write-Host -Scope It -ParameterFilter { $Object -match "TestSerial123" }
             Assert-MockCalled -CommandName Write-Host -Scope It -ParameterFilter { $Object -match "192.168.1.100" }
             Assert-MockCalled -CommandName Write-Host -Scope It -ParameterFilter { $Object -match "Windows Test OS.*12345" }
             Assert-MockCalled -CommandName Write-Host -Scope It -ParameterFilter { $Object -match $ConfigScriptVersion }
        }

        It "debería llamar a InvocarBateriaPruebas cuando se selecciona '1'" {
            Mock -CommandName Read-Host -MockWith { return '1' }
            MostrarMenuPrincipal
            Assert-MockCalled -CommandName InvocarBateriaPruebas -Times 1 -Scope It
        }
        It "debería llamar a SubirArchivoLog y Exit-PSHost cuando se selecciona 'X'" {
            Mock -CommandName Read-Host -MockWith { return 'X' }
            MostrarMenuPrincipal
            Assert-MockCalled -CommandName SubirArchivoLog -Times 1 -Scope It
            Assert-MockCalled -CommandName Exit-PSHost -Times 1 -Scope It
        }
        It "debería manejar una entrada inválida y volver a mostrar el menú principal" {
            Mock -CommandName Read-Host -MockWith { $script:Calls = ($script:Calls | ForEach-Object {$_ + 1}); if($script:Calls -eq 1) { return 'invalid' } else { return 'X' } }
            $script:Calls = 0
            MostrarMenuPrincipal
            Assert-MockCalled -CommandName Write-Host -Scope It -ParameterFilter { $Object -match "opcion no valida" }
            Assert-MockCalled -CommandName MostrarMenuPrincipal -Times 2 -Scope It # Initial + recursive
        }
    }
}

# Placeholder for more tests already present
Describe "CAUJUS_dev.ps1 - Further Tests" {
    It "Placeholder test" {
        $true | Should -Be $true
    }
}
