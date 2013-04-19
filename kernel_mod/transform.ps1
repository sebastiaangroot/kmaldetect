Param(
	[string]$Infile,
	[string]$Outfile
)

#$funct is in format "<type> <functname>(<argtype> [argname], <argtype> [argname]);"
function Get-Arguments
{
	Param(
		[string]$funct
	)

	
	$retval = ""

	#Obtain the substring of the function containing the arguments (without braces)
	$arguments = $funct.SubString($funct.IndexOf("(") + 1, $funct.IndexOf(")") - $funct.IndexOf("(") - 1)
	
	#Create an array of all arguments by splitting the argument string on the comma
	$arglist = $arguments.Split(",")
	
	#For each argument
	for($i = 0; $i -lt $arglist.Length; $i++)
	{
		#If it's void and nothing else, it indicates that no argument should be passed. Immediately break the argument parsing loop
		if ($arglist[$i] -eq "void")
		{
			break
		}
		
		#Break the argument segments up by splitting on the spaces
		$components = $arglist[$i].Split(" ")

		$argname = $components[$components.Length - 1]
		if ($argname -ne "*")
		{
			$argname = $argname.Replace("*", "")
		}

		if ($argname -eq "")
		{
			$argname = "arg$i"
		}
		$retval += "$argname, "
	}
	if ($retval -ne "")
	{
		$retval = $retval.SubString(0, $retval.Length - 2)
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
