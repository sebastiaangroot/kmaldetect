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
		if ($arglist[$i] -eq "void" -AND $arglist.Length -eq 1)
		{
			break
		}
		
		#Break the argument segments up by splitting on the spaces
		$components = $arglist[$i].Split(" ")
		
		$argname = $components[$components.Length - 1]
		
		if ($argname.StartsWith("*"))
		{
			$argname = $argname.SubString(1, $argname.Length - 1)
		}
		
		$retval += "$argname"
		if ($i -lt $arglist.Length - 1)
		{
			$retval += ", "
		}
	}
	
	return $retval
}

function Get-FunctionName
{
	Param(
		[string]$funct
	)
	
	$preargs = $funct.SubString(0, $funct.IndexOf("(") + 1) #"long name("
	$argstring = ""
	$postargs = ")"
	$arglist = @() #List of all formatted args
	
	$args = $funct.SubString($funct.IndexOf("(") + 1, $funct.IndexOf(")") - $funct.IndexOf("(") - 1) #"type *name, type name"
	$args = $args.Split(",")
	#For each arg, we want the following format: type-1 ... type-n (*)name.
	#The problem is that the c compiler has a mapping of all defined types to determine if the last element is a type or argname, which we do not. Looking at the provided functions though, the rule of thumb for typenames seems to be: typename = (standard C type) OR (__typename), so we'll go with that
	for ($i = 0; $i -lt $args.Length; $i++)
	{
		if ($args[$i] -eq "void" -AND $args.Length -eq 1) #nothing but (void) found here
		{
			$arglist += "void"
			break
		}

		$argcomp = $args[$i].Split(" ")
		if ($argcomp[$argcomp.Length - 1].Equals("*")) #If the last element is a single *, it's a pointer. Name it arg$i
		{
			$arglist += ($args[$i] + "arg$i")
		}
		elseif (@("char", "short", "int", "long", "size_t", "char*", "short*", "int*", "long*", "size_t*") -Contains $argcomp[$argcomp.Length - 1])
		{
			$arglist += ($args[$i] + " arg$i")
		}
		elseif ($argcomp[0].Equals("struct") -AND $argcomp.Length -le 2)
		{
			$arglist += ($args[$i] + " arg$i")
		}
		elseif ($argcomp[$argcomp.Length - 1].StartsWith("__"))
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
		$argstring += $arglist[$i]
		if ($i -lt $arglist.Length - 1)
		{
			$argstring += ","
		}
	}
	
	return ($preargs + $argstring + $postargs)
}

$content = Get-Content -Path $Infile
New-Item -Path $Outfile -ItemType file -Force
$count = 1
$total = $content.Length
foreach($line in $content)
{
	Write-Host "Progress: $count / $total"
	$count++
	if ($line.StartsWith("long")) #All syscalls return a long
	{
		$functname = Get-FunctionName -funct $line.Clone()
		
		$refname = $line.Clone()
		$refname = $refname.Replace("hook_", "real_")
		$refname = $refname.SubString(5, $refname.IndexOf('(')-5)
		
		$functpass = "long retval = "
		$functpass += $refname
		$functpass += "("
		$functpass += Get-Arguments -funct $functname
		$functpass += ");"
		
		$functname | Out-File -FilePath $Outfile -Append -Force
		"{" | Out-File -FilePath $Outfile -Append -Force
		"	$functpass" | Out-File -FilePath $Outfile -Append -Force
		"	//Logger here" | Out-File -FilePath $Outfile -Append -Force
		"	return retval;" | Out-File -FilePath $Outfile -Append -Force
		"}" | Out-File -FilePath $Outfile -Append -Force
		"" | Out-File -FilePath $Outfile -Append -Force
	}
}
