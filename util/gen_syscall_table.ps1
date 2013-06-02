Param(
	[string]$Infile,
	[string]$Outfile
)

$content = Get-Content -Path $Infile
New-Item -Path $Outfile -ItemType file -Force

#Print out .sh style switch that translates a syscall name to an index number
$sys_index = ""
"function get_syscall_index" | Out-File -FilePath $Outfile -Append -Force
"{" | Out-File -FilePath $Outfile -Append -Force
"	case `$1 in" | Out-File -FilePath $Outfile -Append -Force
for ($i = 0; $i -lt $content.Length; $i++)
{
	if ($content[$i].StartsWith("#define __NR_") -AND (-NOT ($content[$i+1].Contains("stub_"))))
	{
		$line_substr = $content[$i].Substring($content[$i].IndexOf("__NR_") + 5)
		if ($line_substr.Contains("`t")) #Either substring on the first space or tab character
		{
			$sys_index = $content[$i].Clone()
			$sys_index = $sys_index.Substring($sys_index.IndexOf("`t")).Replace("`t", "")
			"		'" + $line_substr.Substring(0, $line_substr.IndexOf("	")) + "')" | Out-File -FilePath $Outfile -Append -Force
		}
		else
		{
			$sys_index = $content[$i].Clone()
			$sys_index = $sys_index.Substring($sys_index.IndexOf(" ", 10)).Replace(" ", "")
			"		'" + $line_substr.Substring(0, $line_substr.IndexOf(" ")) + "')" | Out-File -FilePath $Outfile -Append -Force
		}
		"			return $sys_index" | Out-File -FilePath $Outfile -Append -Force
		"			;;" | Out-File -FilePath $Outfile -Append -Force
	}
}
"	esac" | Out-File -FilePath $Outfile -Append -Force
"}" | Out-File -FilePath $Outfile -Append -Force