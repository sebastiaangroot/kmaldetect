Param(
	[string]$Infile,
	[string]$Outfile
)

$content = Get-Content $Infile
New-Item -Path $Outfile -ItemType file -Force

foreach ($line in $content)
{
	if (-NOT ($line.Contains("long hook_")))
	{
		continue
	}
	
	$type = $line.SubString(0, 4)
	$functname = $line.Substring(5, $line.IndexOf("(") - 5)
	$arguments = $line.Substring($line.IndexOf("("))
	$functname = $functname.Replace("hook_", "real_")
	$functname = "(*" + $functname + ")"
	$outstring = $type + " " + $functname + $arguments + ";"
	$outstring | Out-File -FilePath $Outfile -Append -Force
}