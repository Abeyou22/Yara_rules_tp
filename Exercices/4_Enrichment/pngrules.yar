rule png_file {
	strings:
		$a_png = {89 50 4E 47} 
	condition:
		$a_png at 0
}

rule jfif_file {
	strings:
		$a = {FF D8 FF E0 ?? ?? 4A 46 49 46 00} 
	condition:
		$a at 0
}
