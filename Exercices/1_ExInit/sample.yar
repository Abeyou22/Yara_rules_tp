rule SectionSample{
  meta:
  /*
    This is a multi-line comment ...
*/
    author = "Descartes"
    description = "Simple YARA rule"

  strings:
    $a = "UVODFRYSIHLNWPEJXQZAKCBGMT"
  
  condition:
   any of them //checks whether a file has any of the above rules //$a or $b or $c
}



rule HexSample : OUI {
  meta:
  /*
    This is a multi-line comment ...
*/
    author = "Descartes"
    description = "YARA rule check false en hexa"
    tags = "OUI"

  strings:
    $b = {66 61 6C 73 65} //false en hexa
  
  condition:
   $b 
}

rule ExampleRule
{
    strings:
        $my_text_string = "text here"
        $my_hex_string = { E2 34 A1 C8 23 FB }

    condition:
        $my_text_string or $my_hex_string
}

//This is a comment