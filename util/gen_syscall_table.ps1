Param(
	[string]$Infile,
	[string]$Outfile
)

$content = Get-Content -Path $Infile
New-Item -Path $Outfile -ItemType file -Force

#Print out .sh style switch that translates a syscall name to an index number
$sys_index = 0
"function get_syscall_index" | Out-File -FilePath $Outfile -Append -Force
"{" | Out-File -FilePath $Outfile -Append -Force
"	case `$sys_name in `$1" | Out-File -FilePath $Outfile -Append -Force
foreach ($line in $content)
{
	if ($line.StartsWith("#define __NR_"))
	{
		$line_substr = $line.Substring($line.IndexOf("__NR_") + 5)
		if ($line_substr.Contains("	")) #Either substring on the first space or tab character
		{
			"		'" + $line_substr.Substring(0, $line_substr.IndexOf("	")) + "')" | Out-File -FilePath $Outfile -Append -Force
		}
		else
		{
			"		'" + $line_substr.Substring(0, $line_substr.IndexOf(" ")) + "')" | Out-File -FilePath $Outfile -Append -Force
		}
		"			return $sys_index" | Out-File -FilePath $Outfile -Append -Force
		$sys_index++
	}
}
"	esac" | Out-File -FilePath $Outfile -Append -Force
"}" | Out-File -FilePath $Outfile -Append -Force