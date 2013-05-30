Param(
	[string]$InUnistd,
	[string]$InSysGen,
	[string]$InSysArchGen,
	[string]$InSysArch,
	[string]$Outfile
)

#All tables must have an equal number of entries. All indexes should refer to the same syscall
[string[]]$SYSCALL_NAMES_TABLE
[string[]]$REFS_TABLE
[string[]]$HOOKS_TABLE

function Get-Arguments-Names-Only
{
	Param(
		[string]$funct
	)

	$retval = ""
	$arglist = @()
	
	$args = $funct.Substring($funct.IndexOf("(") + 1, $funct.IndexOf(")") - $funct.IndexOf("(") - 1)
	
	$args = $args.Split(",")
	
	for ($i = 0; $i -lt $args.Length; $i++)
	{
		if ($args[$i] -eq "void" -AND $args.Length -eq 1)
		{
			break
		}
		
		$components = $args[$i].Split(" ")
				
		if ($components[$components.Length - 1].Equals("*"))
		{
			$arglist += "arg$i"
		}
		elseif (@("char", "short", "int", "long", "size_t", "pid_t", "unsigned", "char*", "short*", "int*", "long*", "size_t*", "pid_t*", "unsigned*") -Contains $components[$components.Length - 1])
		{
			$arglist += "arg$i"
		}
		elseif ($components[0].Equals("struct") -AND $components.Length -le 2)
		{
			$arglist += "arg$i"
		}
		elseif ($components[$components.Length - 1].StartsWith("__"))
		{
			$arglist += "arg$i"
		}
		elseif ($components[$components.Length - 1].EndsWith("_t"))
		{
			$arglist += "arg$i"
		}
		else
		{
			$arglist += $components[$components.Length - 1].Replace("*", "")
		}
	}

	for ($i = 0; $i -lt $arglist.Length; $i++)
	{
		$retval += $arglist[$i]
		if ($i -lt $arglist.Length - 1)
		{
			$retval += ","
		}
	}
	return $retval
}

function Get-Arguments
{
	Param(
		[string]$funct
	)

	$retval = ""
	$arglist = @()
	
	$args = $funct.Substring($funct.IndexOf("(") + 1, $funct.IndexOf(")") - $funct.IndexOf("(") - 1)
	
	$args = $args.Split(",")
	
	for ($i = 0; $i -lt $args.Length; $i++)
	{
		if ($args[$i] -eq "void" -AND $args.Length -eq 1)
		{
			$arglist += "void"
			break
		}

		$components = $args[$i].Split(" ")		
				
		if ($components[$components.Length - 1].Equals("*"))
		{
			$arglist += ($args[$i] + "arg$i")
		}
		elseif (@("char", "short", "int", "long", "size_t", "pid_t", "unsigned", "char*", "short*", "int*", "long*", "size_t*", "pid_t*", "unsigned*") -Contains $components[$components.Length - 1])
		{
			$arglist += ($args[$i] + " arg$i")
		}
		elseif ($components[0].Equals("struct") -AND $components.Length -le 2)
		{
			$arglist += ($args[$i] + " arg$i")
		}
		elseif ($components[$components.Length - 1].StartsWith("__"))
		{
			$arglist += ($args[$i] + " arg$i")
		}
		elseif ($components[$components.Length - 1].EndsWith("_t"))
		{
			$arglist += ($args[$i] + " arg$i")
		}
		else
		{
			$arglist += $args[$i]
		}
	}

	for ($i = 0; $i -lt $arglist.Length; $i++)
	{
		$retval += $arglist[$i]
		if ($i -lt $arglist.Length - 1)
		{
			$retval += ","
		}
	}
	return $retval
}

function Get-SysID
{
	Param(
		[string]$funct
	)
	
	$unifile = Get-Content $InUnistd
	$output
	for ($i = 0; $i -lt $unifile.Length; $i++)
	{
		if ($unifile[$i].Contains($funct))
		{
			if ($unifile[$i - 1].Contains("`t"))
			{
				$output = $unifile[$i - 1]
				$output = $output.Substring($output.IndexOf("`t")).Replace("`t", "")
				Write-Output $output
			}
			else
			{
				$output = $unifile[$i - 1]
				$output = $output.Substring($output.IndexOf(" ", 10)).Replace(" ", "")
				Write-Output $output
			}
		}
	}
}

function Get-NrName
{
	Param(
		[string]$sysName
	)
	
	$unifile = Get-Content $InUnistd
	$found = $false
	foreach ($line in $unifile)
	{
		if ($line.Contains($sysName))
		{
			$found = $true
			$output = $line.Substring($line.IndexOf("(") + 1, $line.IndexOf(",") - ($line.IndexOf("(") + 1))
			return $output
		}
	}
	
	Write-Warning "$sysName NrName not found!"
	return "__NR_open"
}

function Print-Includes
{
	Write-Output "#include <asm/unistd.h>"
	Write-Output "#include <linux/syscalls.h>"
	Write-Output "#include <asm/thread_info.h>"
	Write-Output "#include `"nl_iface.h`""
	Write-Output "#include `"utils.h`""
	Write-Output "#include `"kmaldetect.h`""
}

function Print-FunctPointers
{
	Param(
		[string[]]$contentUnistd,
		[string[]]$contentSysArch,
		[string[]]$contentSysArchGen,
		[string[]]$contentSysGen
	)
	[string[]]$outputArray = @()
	foreach($line in $contentUnistd)
	{
		if ($line.StartsWith("__SYSCALL("))
		{
			$found = $false
			[string]$prototype = ""
			$functName = $line.Substring($line.IndexOf(",") + 2)
			$functName = $functName.Substring(0, $functName.IndexOf(")"))
			for ($i = 0; $i -lt $contentSysArch.Length; $i++)
			{
				if ($contentSysArch[$i].Contains($functName + "("))
				{
					$prototype = $contentSysArch[$i]
					while (-NOT $contentSysArch[$i].Contains(");"))
					{
						$i++
						$prototype += " " + $contentSysArch[$i].Replace("`t", "")
					}
					
					$found = $true
				}
			}
			if (-NOT $found)
			{
				for ($i = 0; $i -lt $contentSysArchGen.Length; $i++)
				{
					if ($contentSysArchGen[$i].Contains($functName + "("))
					{
						$prototype = $contentSysArchGen[$i]
						while (-NOT $contentSysArchGen[$i].Contains(");"))
						{
							$i++
							$prototype += " " + $contentSysArchGen[$i].Replace("`t", "")
						}
						$found = $true
					}
				}
			}
			if (-NOT $found)
			{
				for ($i = 0; $i -lt $contentSysGen.Length; $i++)
				{
					if ($contentSysGen[$i].Contains($functName + "("))
					{
						$prototype = $contentSysGen[$i]
						while (-NOT $contentSysGen[$i].Contains(");"))
						{
							$i++
							$prototype += " " + $contentSysGen[$i].Replace("`t", "")
						}
						$found = $true
					}
				}
			}
			if ($found)
			{
				$duplicate = $false
				
				if ($prototype.StartsWith("asmlinkage "))
				{
					$prototype = $prototype.Substring(11)
				}
				
				$prototype = $prototype.Insert($prototype.IndexOf("("), ")")
				$prototype = $prototype.Insert($prototype.IndexOf($functName), "(*ref_")
				$prototype = $prototype.Insert($prototype.IndexOf(";"), " = NULL")
				
				foreach ($entry in $outputArray)
				{
					if ($entry.Equals($prototype))
					{
						$duplicate = $true
					}
				}
				
				if (-NOT $duplicate)
				{
					$outputArray += $prototype
				}
			}
		}
	}
	Write-Output $outputArray
}

function Print-HookFunctions
{
	Param(
		[string[]]$functPointers
	)
	
	[string[]]$output
	foreach ($funct in $functPointers)
	{
		$output = @()
		$fullArgs = Get-Arguments -funct $funct.Substring($funct.IndexOf(")(") + 1)
		$plainArgs = Get-Arguments-Names-Only -funct $funct.Substring($funct.IndexOf(")(") + 1)
		
		$syscallName = $funct.Substring($funct.IndexOf("ref_") + 4, $funct.IndexOf(")") - ($funct.IndexOf("ref_") + 4))
		$retType = $funct.Substring(0, $funct.IndexOf(" "))
		
		$hookName = "hook_" + $syscallName
		$refName = $funct.Substring($funct.IndexOf("ref_"), $funct.IndexOf(")") - ($funct.IndexOf("ref_")))
		
		$sysid = Get-SysID -funct $syscallName
				
		$output += ""
		$output += "$retType $hookName($fullArgs)"
		$output += "{"
		$output += "`t$retType retval = $refName($plainArgs);"
		$output += "`tif (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)"
		$output += "`t{"
		$output += "`t`tSYSCALL data;"
		$output += "`t`tdata.sys_id = $sysid;"
		$output += "`t`tdata.inode = get_inode();"
		$output += "`t`tdata.pid = current->pid;"
		$output += "`t`tdata.mem_loc = 0;"
		$output += "`t`tmaldetect_nl_send_syscall(&data);"
		$output += "`t}"
		$output += "`treturn retval;"
		$output += "}"
		$output | Out-File -FilePath $Outfile -Append -Force
	}
}

function Print-RegUnreg
{
	Param(
		[string[]]$functPointers
	)
	
	[string[]]$output = @()
	$output += ""
	$output += "void reg_hooks(unsigned long **syscall_table)"
	$output += "{"
	foreach ($funct in $functPointers)
	{
		$refName = $funct.Substring($funct.IndexOf("ref_"), $funct.IndexOf(")") - ($funct.IndexOf("ref_")))
		$nrName = Get-NrName -sysName $refName.Substring(4)
		$hookName = $refName.Replace("ref_", "hook_")
		
		$output += "`t$refname = (void *)syscall_table[$nrName];"
		$output += "`tsyscall_table[$nrName] = (unsigned long *)$hookName"
	}
	$output += "}"
	$output | Out-File -FilePath $Outfile -Append -Force
	$output = @()
	
	$output += ""
	$output += "void unreg_hooks(unsigned long **syscall_table)"
	$output += "{"	
	foreach ($funct in $functPointers)
	{
		$refName = $funct.Substring($funct.IndexOf("ref_"), $funct.IndexOf(")") - ($funct.IndexOf("ref_")))
		$nrName = Get-NrName -sysName $refName.Substring(4)
		
		$output += "`tsyscall_table[$nrName] = (unsigned long *)$refName;"
	}
	$output += "}"
	$output | Out-File -FilePath $Outfile -Append -Force
}

New-Item -Path $OutFile -ItemType file -Force
Print-Includes | Out-File -FilePath $Outfile -Append -Force
$functPointers = Print-FunctPointers -contentUnistd (Get-Content $InUnistd) -contentSysArch (Get-Content $InSysArch) -contentSysGen (Get-Content $inSysGen) -contentSysArchGen (Get-Content $inSysArchGen)
$functPointers | Out-File -FilePath $OutFile -Append -Force
Print-HookFunctions -functPointers $functPointers
Print-RegUnreg -functPointers $functPointers