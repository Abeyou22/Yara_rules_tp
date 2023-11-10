rule png_file {
	strings:
		$a = {89 50 4E 47} 
	condition:
		$a
}

rule jfif_file {
	strings:
		$a = {FF D8 FF E0 ?? ?? 4A 46 49 46 00} 
	condition:
		$a
}
