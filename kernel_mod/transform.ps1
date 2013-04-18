Param(
	[string]$Infile,
	[string]$Outfile
)

function Strip-Arguments
{
	Param(
		[string]$funct
	)
	
	$retval = ""
	$arguments = $funct.SubString($funct.IndexOf("(") + 1, $funct.IndexOf(")") - $funct.IndexOf("(") - 1)
	
	$arglist = $arguments.Split(",")
	
	foreach($arg in $arglist)
	{
		if ($arg -eq "void")
		{
			break
		}
		
		$components = $arg.Split(" ")
		$argname = $components[$components.Length - 1]
		if ($argname -ne "*")
		{
			$argname = $argname.Replace("*", "")
		}
		$retval += "$argname, "
	}
	if ($retval -ne "")
	{
		$retval = $retval.SubString(0, $retval.Length-2)
	}
	return $retval
}

$content = Get-Content -Path $Infile
$count = 1
$total = $content.Length
foreach($line in $content)
{
	Write-Host "Progress: $count / $total"
	$count++
	if ($line.StartsWith("long")) #All syscalls return a long
	{
		$functname = $line.Clone()
		
		$refname = $line.Clone()
		$refname = $refname.Replace("hook_", "real_")
		$refname = $refname.SubString(5, $refname.IndexOf('(')-5)
		
		$returnline = "return "
		$returnline += $refname
		$returnline += "("
		$returnline += Strip-Arguments -funct $functname
		$returnline += ");"
		
		$functname | Out-File -FilePath $Outfile -Append -Force
		"{" | Out-File -FilePath $Outfile -Append -Force
		"	//Logger here" | Out-File -FilePath $Outfile -Append -Force
		"	$returnline" | Out-File -FilePath $Outfile -Append -Force
		"}" | Out-File -FilePath $Outfile -Append -Force
		"" | Out-File -FilePath $Outfile -Append -Force
	}
}