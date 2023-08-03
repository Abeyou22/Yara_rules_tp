rule png_file {
	strings:
		$a = {89 50 4E 47} 
	condition:
		$a at 0
}
