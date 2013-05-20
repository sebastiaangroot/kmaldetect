Param(
	[string]$InUnistd,
	[string]$InSysGen,
	[string]$InSysArch,
	[string]$Outfile
)

[string[]]$SYSCALL_TABLE
[string[]]$PROTOTYPE_TABLE

function Get-Syscall-Table
{
	Param(
		[string[]]$contentUnistd
	)
	
	$table = @()
	
	foreach ($line in $contentUnistd)
	{
		if ($line.StartsWith("#define __NR_"))
		{
			$syscall = $line.Replace("#define __NR_", "")
			if ($syscall.Contains(" ")) #whitespace
			{
				$syscall = $syscall.Substring(0, $syscall.IndexOf(" "))
			}
			elseif ($syscall.Contains("`t")) #tab
			{
				$syscall = $syscall.Substring(0, $syscall.IndexOf("`t"))
			}
			$table += $syscall
		}
	}
	
	return $table
}

function Get-Syscall-Funct-By-Name
{
	Param(
		[string]$name,
		[string[]]$content
	)
	
	for ($i = 0; $i -lt $content.Length; $i++)
	{
		if ($content[$i].Contains($name) -AND $content[$i].Contains("asmlinkage long"))
		{
			$preargs = $content[$i].Substring(11, $content[$i].IndexOf("(") - 11)
			
			[string]$argstring = $content[$i].Substring($content[$i].IndexOf("("))

			if (-NOT $content[$i].Contains(");"))
			{
				do {
					$i++
					$argstring += " " + $content[$i].Replace("`t", "")
				} while (-NOT $content[$i].Contains(");"))
			}
			
			return [string]($preargs + $argstring)
		}
	}

	return $null
}

function Get-Syscall-Functs-By-Name
{
	Param(
		[string[]]$syscallNames,
		[string[]]$prototypesGeneric,
		[string[]]$prototypesArch
	)
	
	$table = @()
	[boolean]$found = $false
	
	foreach($name in $syscallNames)
	{
		$name = "sys_" + $name
		
		$prot = Get-Syscall-Funct-By-Name -name $name -content $prototypesArch
		
		if ($prot -eq $null)
		{
			$prot = Get-Syscall-Funct-By-Name -name $name -content $prototypesGeneric
		}
		
		if ($prot -ne $null)
		{
			$table += $prot
		}
	}
	
	return $table
}

function Add-Headers
{
	Param(
		[string]$Outfile
	)
	
	"#include <linux/kernel.h>" | Out-File -FilePath $Outfile -Append -Force
	"#include <linux/syscalls.h>" | Out-File -FilePath $Outfile -Append -Force
	"#include <asm/syscalls.h>" | Out-File -FilePath $Outfile -Append -Force
	"#include <asm/unistd.h>" | Out-File -FilePath $Outfile -Append -Force
	"" | Out-File -FilePath $Outfile -Append -Force
}

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

function Add-Hooks
{
	Param(
		[string[]]$Prototypes,
		[string]$Outfile
	)

	foreach ($function in $Prototypes)
	{
		$defArgs = Get-Arguments -funct $function
		$retvalCall = "long retval = " + $function.Substring(5, $function.IndexOf("(") - 5 + 1) + (Get-Arguments-Names-Only -funct $function) + ");"
		
		$hookDefinition = $function.Substring(0, $function.IndexOf("(") + 1).Replace("sys_", "hook_") + $defArgs + ")"
		
		"" | Out-File -FilePath $Outfile -Append -Force
		$hookDefinition | Out-File -FilePath $Outfile -Append -Force
		"{" | Out-File -FilePath $Outfile -Append -Force
		"`t" + $retvalCall | Out-File -FilePath $Outfile -Append -Force
		"`treturn retval;" | Out-File -FilePath $Outfile -Append -Force
		"}" | Out-File -FilePath $Outfile -Append -Force
	}
}

function Add-RegFunctions
{
	Param(
		[string[]]$syscallNames,
		[string]$Outfile
	)
	
	"void reg_hooks(unsigned long **sys_call_table)" | Out-File -FilePath $Outfile -Append -Force
	"{" | Out-File -FilePath $Outfile -Append -Force
	foreach($syscallname in $syscallNames)
	{
		$functName = "(void *)hook_" + $syscallName		
		"`tsys_call_table[__NR_$syscallName] = $functName" | Out-File -FilePath $Outfile -Append -Force
	}
	"}" | Out-File -FilePath $Outfile -Append -Force
	"" | Out-File -FilePath $Outfile -Append -Force
	
	"void unreg_hooks(unsigned long **sys_call_table)" | Out-File -FilePath $Outfile -Append -Force
	"{" | Out-File -FilePath $Outfile -Append -Force
	foreach($syscallname in $syscallNames)
	{
		$functName = "(void *)sys_" + $syscallName		
		"`tsys_call_table[__NR_$syscallName] = $functName" | Out-File -FilePath $Outfile -Append -Force
	}
	"}" | Out-File -FilePath $Outfile -Append -Force
	"" | Out-File -FilePath $Outfile -Append -Force
}

$SYSCALL_TABLE = Get-Syscall-Table -contentUnistd (Get-Content -Path $InUnistd)
$PROTOTYPE_TABLE = Get-Syscall-Functs-By-Name -syscallNames $SYSCALL_TABLE -prototypesGeneric (Get-Content -Path $InSysGen) -prototypesArch (Get-Content -Path $InSysArch)
New-Item -Path $Outfile -ItemType file -Force

Add-Headers -Outfile $Outfile
$PROTOTYPE_TABLE | Out-File -FilePath $Outfile -Append -Force
Add-Hooks -Prototypes $PROTOTYPE_TABLE -Outfile $Outfile
Add-RegFunctions -syscallNames $SYSCALL_TABLE -Outfile $Outfile