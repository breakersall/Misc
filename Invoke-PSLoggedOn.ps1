function Convert-SidToName {
<#
    .SYNOPSIS
    
        Converts a security identifier (SID) to a group/user name.

    .PARAMETER SID
    
        The SID to convert.

    .EXAMPLE

        PS C:\> Convert-SidToName S-1-5-21-2620891829-2411261497-1773853088-1105
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [String]
        $SID
    )

    process {
        try {
            $SID2 = $SID.trim('*')

            # try to resolve any built-in SIDs first
            #   from https://support.microsoft.com/en-us/kb/243330
            Switch ($SID2)
            {
                'S-1-0'         { 'Null Authority' }
                'S-1-0-0'       { 'Nobody' }
                'S-1-1'         { 'World Authority' }
                'S-1-1-0'       { 'Everyone' }
                'S-1-2'         { 'Local Authority' }
                'S-1-2-0'       { 'Local' }
                'S-1-2-1'       { 'Console Logon ' }
                'S-1-3'         { 'Creator Authority' }
                'S-1-3-0'       { 'Creator Owner' }
                'S-1-3-1'       { 'Creator Group' }
                'S-1-3-2'       { 'Creator Owner Server' }
                'S-1-3-3'       { 'Creator Group Server' }
                'S-1-3-4'       { 'Owner Rights' }
                'S-1-4'         { 'Non-unique Authority' }
                'S-1-5'         { 'NT Authority' }
                'S-1-5-1'       { 'Dialup' }
                'S-1-5-2'       { 'Network' }
                'S-1-5-3'       { 'Batch' }
                'S-1-5-4'       { 'Interactive' }
                'S-1-5-6'       { 'Service' }
                'S-1-5-7'       { 'Anonymous' }
                'S-1-5-8'       { 'Proxy' }
                'S-1-5-9'       { 'Enterprise Domain Controllers' }
                'S-1-5-10'      { 'Principal Self' }
                'S-1-5-11'      { 'Authenticated Users' }
                'S-1-5-12'      { 'Restricted Code' }
                'S-1-5-13'      { 'Terminal Server Users' }
                'S-1-5-14'      { 'Remote Interactive Logon' }
                'S-1-5-15'      { 'This Organization ' }
                'S-1-5-17'      { 'This Organization ' }
                'S-1-5-18'      { 'Local System' }
                'S-1-5-19'      { 'NT Authority' }
                'S-1-5-20'      { 'NT Authority' }
                'S-1-5-80-0'    { 'All Services ' }
                'S-1-5-32-544'  { 'BUILTIN\Administrators' }
                'S-1-5-32-545'  { 'BUILTIN\Users' }
                'S-1-5-32-546'  { 'BUILTIN\Guests' }
                'S-1-5-32-547'  { 'BUILTIN\Power Users' }
                'S-1-5-32-548'  { 'BUILTIN\Account Operators' }
                'S-1-5-32-549'  { 'BUILTIN\Server Operators' }
                'S-1-5-32-550'  { 'BUILTIN\Print Operators' }
                'S-1-5-32-551'  { 'BUILTIN\Backup Operators' }
                'S-1-5-32-552'  { 'BUILTIN\Replicators' }
                'S-1-5-32-554'  { 'BUILTIN\Pre-Windows 2000 Compatible Access' }
                'S-1-5-32-555'  { 'BUILTIN\Remote Desktop Users' }
                'S-1-5-32-556'  { 'BUILTIN\Network Configuration Operators' }
                'S-1-5-32-557'  { 'BUILTIN\Incoming Forest Trust Builders' }
                'S-1-5-32-558'  { 'BUILTIN\Performance Monitor Users' }
                'S-1-5-32-559'  { 'BUILTIN\Performance Log Users' }
                'S-1-5-32-560'  { 'BUILTIN\Windows Authorization Access Group' }
                'S-1-5-32-561'  { 'BUILTIN\Terminal Server License Servers' }
                'S-1-5-32-562'  { 'BUILTIN\Distributed COM Users' }
                'S-1-5-32-569'  { 'BUILTIN\Cryptographic Operators' }
                'S-1-5-32-573'  { 'BUILTIN\Event Log Readers' }
                'S-1-5-32-574'  { 'BUILTIN\Certificate Service DCOM Access' }
                'S-1-5-32-575'  { 'BUILTIN\RDS Remote Access Servers' }
                'S-1-5-32-576'  { 'BUILTIN\RDS Endpoint Servers' }
                'S-1-5-32-577'  { 'BUILTIN\RDS Management Servers' }
                'S-1-5-32-578'  { 'BUILTIN\Hyper-V Administrators' }
                'S-1-5-32-579'  { 'BUILTIN\Access Control Assistance Operators' }
                'S-1-5-32-580'  { 'BUILTIN\Access Control Assistance Operators' }
                Default { 
                    $Obj = (New-Object System.Security.Principal.SecurityIdentifier($SID2))
                    $Obj.Translate( [System.Security.Principal.NTAccount]).Value
                }
            }
        }
        catch {
            # Write-Warning "Invalid SID: $SID"
            $SID
        }
    }
}

function New-InMemoryModule
{
    <#
        .SYNOPSIS

        Creates an in-memory assembly and module

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
 
        .DESCRIPTION

        When defining custom enums, structs, and unmanaged functions, it is
        necessary to associate to an assembly module. This helper function
        creates an in-memory module that can be passed to the 'enum',
        'struct', and Add-Win32Type functions.

        .PARAMETER ModuleName

        Specifies the desired name for the in-memory assembly and module. If
        ModuleName is not provided, it will default to a GUID.

        .EXAMPLE

        $Module = New-InMemoryModule -ModuleName Win32
    #>

    [OutputType([Reflection.Emit.ModuleBuilder])]
    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
# Author: Matthew Graeber (@mattifestation)
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
    <#
        .SYNOPSIS

        Creates a .NET type for an unmanaged Win32 function.

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: func
 
        .DESCRIPTION

        Add-Win32Type enables you to easily interact with unmanaged (i.e.
        Win32 unmanaged) functions in PowerShell. After providing
        Add-Win32Type with a function signature, a .NET type is created
        using reflection (i.e. csc.exe is never called like with Add-Type).

        The 'func' helper function can be used to reduce typing when defining
        multiple function definitions.

        .PARAMETER DllName

        The name of the DLL.

        .PARAMETER FunctionName

        The name of the target function.

        .PARAMETER ReturnType

        The return type of the function.

        .PARAMETER ParameterTypes

        The function parameters.

        .PARAMETER NativeCallingConvention

        Specifies the native calling convention of the function. Defaults to
        stdcall.

        .PARAMETER Charset

        If you need to explicitly call an 'A' or 'W' Win32 function, you can
        specify the character set.

        .PARAMETER SetLastError

        Indicates whether the callee calls the SetLastError Win32 API
        function before returning from the attributed method.

        .PARAMETER Module

        The in-memory module that will host the functions. Use
        New-InMemoryModule to define an in-memory module.

        .PARAMETER Namespace

        An optional namespace to prepend to the type. Add-Win32Type defaults
        to a namespace consisting only of the name of the DLL.

        .EXAMPLE

        $Mod = New-InMemoryModule -ModuleName Win32

        $FunctionDefinitions = @(
        (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
        (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
        (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
        )

        $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
        $Kernel32 = $Types['kernel32']
        $Ntdll = $Types['ntdll']
        $Ntdll::RtlGetCurrentPeb()
        $ntdllbase = $Kernel32::GetModuleHandle('ntdll')
        $Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

        .NOTES

        Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

        When defining multiple function prototypes, it is ideal to provide
        Add-Win32Type with an array of function signatures. That way, they
        are all incorporated into the same in-memory module.
    #>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [Reflection.Emit.ModuleBuilder]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        # Define one type for each DLL
        if (!$TypeHash.ContainsKey($DllName))
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
            }
            else
            {
                $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
            }
        }

        $Method = $TypeHash[$DllName].DefineMethod(
            $FunctionName,
            'Public,Static,PinvokeImpl',
            $ReturnType,
            $ParameterTypes)

        # Make each ByRef parameter an Out parameter
        $i = 1
        foreach($Parameter in $ParameterTypes)
        {
            if ($Parameter.IsByRef)
            {
                [void] $Method.DefineParameter($i, 'Out', $null)
            }

            $i++
        }

        $DllImport = [Runtime.InteropServices.DllImportAttribute]
        $SetLastErrorField = $DllImport.GetField('SetLastError')
        $CallingConventionField = $DllImport.GetField('CallingConvention')
        $CharsetField = $DllImport.GetField('CharSet')
        if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

        # Equivalent to C# version of [DllImport(DllName)]
        $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
        $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
            $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
            [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
            [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

        $Method.SetCustomAttribute($DllImportAttribute)
    }

    END
    {
        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            
            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


# A helper function used to reduce typing while defining struct
# fields.
# Author: Matthew Graeber (@mattifestation)
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

# Author: Matthew Graeber (@mattifestation)
function struct
{
    <#
        .SYNOPSIS

        Creates an in-memory struct for use in your PowerShell session.

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: field
 
        .DESCRIPTION

        The 'struct' function facilitates the creation of structs entirely in
        memory using as close to a "C style" as PowerShell will allow. Struct
        fields are specified using a hashtable where each field of the struct
        is comprosed of the order in which it should be defined, its .NET
        type, and optionally, its offset and special marshaling attributes.

        One of the features of 'struct' is that after your struct is defined,
        it will come with a built-in GetSize method as well as an explicit
        converter so that you can easily cast an IntPtr to the struct without
        relying upon calling SizeOf and/or PtrToStructure in the Marshal
        class.

        .PARAMETER Module

        The in-memory module that will host the struct. Use
        New-InMemoryModule to define an in-memory module.

        .PARAMETER FullName

        The fully-qualified name of the struct.

        .PARAMETER StructFields

        A hashtable of fields. Use the 'field' helper function to ease
        defining each field.

        .PARAMETER PackingSize

        Specifies the memory alignment of fields.

        .PARAMETER ExplicitLayout

        Indicates that an explicit offset for each field will be specified.

        .EXAMPLE

        $Mod = New-InMemoryModule -ModuleName Win32

        $ImageDosSignature = enum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
        DOS_SIGNATURE =    0x5A4D
        OS2_SIGNATURE =    0x454E
        OS2_SIGNATURE_LE = 0x454C
        VXD_SIGNATURE =    0x454C
        }

        $ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
        e_magic =    field 0 $ImageDosSignature
        e_cblp =     field 1 UInt16
        e_cp =       field 2 UInt16
        e_crlc =     field 3 UInt16
        e_cparhdr =  field 4 UInt16
        e_minalloc = field 5 UInt16
        e_maxalloc = field 6 UInt16
        e_ss =       field 7 UInt16
        e_sp =       field 8 UInt16
        e_csum =     field 9 UInt16
        e_ip =       field 10 UInt16
        e_cs =       field 11 UInt16
        e_lfarlc =   field 12 UInt16
        e_ovno =     field 13 UInt16
        e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
        e_oemid =    field 15 UInt16
        e_oeminfo =  field 16 UInt16
        e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
        e_lfanew =   field 18 Int32
        }

        # Example of using an explicit layout in order to create a union.
        $TestUnion = struct $Mod TestUnion @{
        field1 = field 0 UInt32 0
        field2 = field 1 IntPtr 0
        } -ExplicitLayout

        .NOTES

        PowerShell purists may disagree with the naming of this function but
        again, this was developed in such a way so as to emulate a "C style"
        definition as closely as possible. Sorry, I'm not going to name it
        New-Struct. :P
    #>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [Reflection.Emit.ModuleBuilder]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}




$Mod = New-InMemoryModule -ModuleName Win32

# all of the Win32 API functions we need
$FunctionDefinitions = @(
    (func netapi32 NetSessionEnum ([Int]) @([string], [string], [string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr]))
)

# the NetSessionEnum result structure
$SESSION_INFO_10 = struct $Mod SESSION_INFO_10 @{
    sesi10_cname = field 0 String -MarshalAs @('LPWStr')
    sesi10_username = field 1 String -MarshalAs @('LPWStr')
    sesi10_time = field 2 UInt32
    sesi10_idle_time = field 3 UInt32
}

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Netapi32 = $Types['netapi32']
function Get-NameField {
    # function that attempts to extract the appropriate field name
    # from various passed objects. This is so functions can have
    # multiple types of objects passed on the pipeline.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        $Object
    )
    process {
        if($Object) {
            if ( [bool]($Object.PSobject.Properties.name -match "dnshostname") ) {
                # objects from Get-NetComputer
                $Object.dnshostname
            }
            elseif ( [bool]($Object.PSobject.Properties.name -match "name") ) {
                # objects from Get-NetDomainController
                $Object.name
            }
            else {
                # strings and catch alls
                $Object
            }
        }
        else {
            return $Null
        }
    }
}
function Get-NetSession {
<#
    .SYNOPSIS

        This function will execute the NetSessionEnum Win32API call to query
        a given host for active sessions on the host.
        Heavily adapted from dunedinite's post on stackoverflow (see LINK below)

    .PARAMETER ComputerName

        The ComputerName to query for active sessions.

    .PARAMETER UserName

        The user name to filter for active sessions.

    .OUTPUTS

        SESSION_INFO_10 structure. A representation of the SESSION_INFO_10
        result structure which includes the host and username associated
        with active sessions.

    .EXAMPLE

        PS C:\> Get-NetSession

        Returns active sessions on the local host.

    .EXAMPLE

        PS C:\> Get-NetSession -ComputerName sqlserver

        Returns active sessions on the 'sqlserver' host.

    .LINK

        http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = 'localhost',

        [String]
        $UserName = ''
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
    }

    process {

        # process multiple host object types from the pipeline
        $ComputerName = Get-NameField -Object $ComputerName

        # arguments for NetSessionEnum
        $QueryLevel = 10
        $PtrInfo = [IntPtr]::Zero
        $EntriesRead = 0
        $TotalRead = 0
        $ResumeHandle = 0

        # get session information
        $Result = $Netapi32::NetSessionEnum($ComputerName, '', $UserName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

        # Locate the offset of the initial intPtr
        $Offset = $PtrInfo.ToInt64()

        Write-Debug "Get-NetSession result: $Result"

        # 0 = success
        if (($Result -eq 0) -and ($Offset -gt 0)) {

            # Work out how mutch to increment the pointer by finding out the size of the structure
            $Increment = $SESSION_INFO_10::GetSize()

            # parse all the result structures
            for ($i = 0; ($i -lt $EntriesRead); $i++) {
                # create a new int ptr at the given offset and cast
                # the pointer as our result structure
                $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                $Info = $NewIntPtr -as $SESSION_INFO_10

                # return all the sections of the structure
                $Info | Select-Object *
                $Offset = $NewIntPtr.ToInt64()
                $Offset += $Increment

            }
            # free up the result buffer
            $Null = $Netapi32::NetApiBufferFree($PtrInfo)
        }
        else
        {
            switch ($Result) {
                (5)           {Write-Debug 'The user does not have access to the requested information.'}
                (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
                (87)          {Write-Debug 'The specified parameter is not valid.'}
                (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
                (8)           {Write-Debug 'Insufficient memory is available.'}
                (2312)        {Write-Debug 'A session does not exist with the computer name.'}
                (2351)        {Write-Debug 'The computer name is not valid.'}
                (2221)        {Write-Debug 'Username not found.'}
                (53)          {Write-Debug 'Hostname could not be found'}
            }
        }
    }
}
function Get-LoggedOnLocal {
<#
    .SYNOPSIS

        This function will query the HKU registry values to retrieve the local
        logged on users SID and then attempt and reverse it.
        Adapted technique from Sysinternal's PSLoggedOn script. Benefit over
		using the NetWkstaUserEnum API (Get-NetLoggedon) of less user privileges
		required.

		
        Note: This function requires only domain user rights on the
        machine you're enumerating.
		
    Function: Get-LoggedOnLocal
	Author: Matt Kelly, @BreakersAll; with code used from @harmj0y's PowerView
	Required Dependencies: Some PowerView Dependencies.
	
	.PARAMETER ComputerName

        The ComputerName to query for active sessions.

    .EXAMPLE

        PS C:\> Get-LoggedOnLocal

        Returns active sessions on the local host.

    .EXAMPLE

        PS C:\> Get-LoggedOnLocal -ComputerName sqlserver

        Returns active sessions on the 'sqlserver' host.

#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = 'localhost'
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
    }

    process {

        # process multiple host object types from the pipeline
        $ComputerName = Get-NameField -Object $ComputerName
		Write-Host "$ComputerName"
		# retrieve HKU remote registry values
		$Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', "$ComputerName")
        
		# sort out bogus sid's like _class
		$UserSID = $Reg.GetSubKeyNames() | ? { $_ -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }
        
		# if successful, convert sid and print output
		if ($UserSID) {
			$UserName = Convert-SidToName $UserSID
		
			$LocalLoggedOnUser = New-Object PSObject
			$LocalLoggedOnUser | Add-Member Noteproperty 'ComputerName' $ComputerName
			$LocalLoggedOnUser | Add-Member Noteproperty 'UserName' $UserName
			$LocalLoggedOnUser | Add-Member Noteproperty 'UserSID' $UserSID
			$LocalLoggedOnUser
		}
		else {
			Write-Debug "Could not retrieve values for $ComputerName"
		}

        Write-Debug "UserSIDs retrieved result: $Reg.GetSubKeyNames()"
    }
}
function Invoke-PSLoggedOn {
<#
    .SYNOPSIS

        This function replicates PSLoggedOn functionality, and leverages 
        Get-NetSession (netsessionenum) and remote registry values.
        Same actions as PSLoggedOn except in PowerShell.

        Note: This function requires only domain user rights on the
        machine you're enumerating.
			
    Function: Invoke-PSLoggedOn
	Author: Matt Kelly, @BreakersAll; with code used from @harmj0y's PowerView
	Required Dependencies: Some PowerView Dependencies. PSv2
	
    .PARAMETER ComputerName

        The ComputerName to query for active sessions.

    .EXAMPLE

        PS C:\> Invoke-PSLoggedOn

        Returns active sessions on the local host.

    .EXAMPLE

        PS C:\> Invoke-PSLoggedOn -ComputerName sqlserver

        Returns active sessions on the 'sqlserver' host.

#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = 'localhost'
    )
	
	begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
    }

    process {

        # process multiple host object types from the pipeline
        $ComputerName = Get-NameField -Object $ComputerName
		
		$LoggedOnLocal = Get-LoggedOnLocal $ComputerName
		$NetSessionUsers = Get-NetSession $ComputerName
		
		Write-Host "Users logged on locally:"
		$LoggedOnLocal
		Write-Host ""
		Write-Host "Users logged on via resource shares:"
		$NetSessionUsers
    }
}